#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>

// включение или выключение отладки (1 = вкл, 0 = выкл)
#define DEBUG 0
#if DEBUG
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

#define MAX_TOKENS 1024
#define MAX_CMD_LEN 8192

typedef enum { TOKEN_WORD, TOKEN_PIPE, TOKEN_REDIRECT_OUT, TOKEN_REDIRECT_APPEND,
               TOKEN_REDIRECT_IN, TOKEN_AND, TOKEN_OR, TOKEN_SEMICOLON, TOKEN_BG,
               TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_END } TokenType;
typedef struct { TokenType type; char *value; } Token;

typedef enum { NODE_SIMPLE, NODE_PIPELINE, NODE_REDIRECT, NODE_AND, NODE_OR,
               NODE_SEQ, NODE_BG, NODE_SUBSHELL } NodeType;
typedef struct Node {
    NodeType type;
    union {
        struct { char **args; int argc; } simple;
        struct { struct Node **commands; int count; } pipeline;
        struct { struct Node *cmd; char *input_file; char *output_file; int append; } redirect;
        struct { struct Node *left; struct Node *right; } binary;
        struct { struct Node *cmd; } subshell;
    } data;
} Node;

Token tokens[MAX_TOKENS];
int token_count = 0, current_token = 0;
char *current_dir = NULL;

void parse_tokens(char *line);
Node *parse_command(void);
Node *parse_conditional(void);
Node *parse_pipeline(void);
Node *parse_simple(void);
Node *parse_subshell(void);
Token next_token(void);
Token peek_token(void);
void free_tokens(void);
void free_node(Node *node);
int execute_node(Node *node, int is_background);
int execute_simple(char **args, int is_background);
int execute_pipeline(Node **commands, int count, int is_background);
void handle_sigchld(int sig);
void setup_signal_handlers(void);
int is_builtin(const char *cmd);
int execute_builtin(char **args);
int builtin_cd(char **args);
int builtin_exit(char **args);

static int wait_status(pid_t pid)
{
    void (*old)(int) = signal(SIGCHLD, SIG_DFL);
    int status = 1;
    if (waitpid(pid, &status, 0) == -1) perror("waitpid");
    signal(SIGCHLD, old);
    return WEXITSTATUS(status);
}

int main() {
    char line[MAX_CMD_LEN];
    setup_signal_handlers();
    current_dir = getcwd(NULL, 0);
    while (true) {
        if (isatty(STDOUT_FILENO)) { printf("> "); fflush(stdout); }
        if (!fgets(line, sizeof(line), stdin)) { printf("\n"); break; }
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;
        parse_tokens(line);
        if (token_count == 0) continue;
        current_token = 0;
        Node *cmd = parse_command();
        if (cmd) { execute_node(cmd, 0); free_node(cmd); }
        free_tokens();
    }
    free(current_dir);
    return 0;
}

void setup_signal_handlers(void) {
    signal(SIGCHLD, handle_sigchld);
    signal(SIGINT, SIG_IGN);   // полное игнорирование ctrl + c
}
void handle_sigchld(int sig) {
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    errno = saved;
}

void parse_tokens(char *line) {
    token_count = 0;
    char *p = line;
    while (*p && token_count < MAX_TOKENS) {
        while (isspace((unsigned char)*p)) ++p;
        if (*p == '\0') break;
        if (strncmp(p, "||", 2) == 0) {
            tokens[token_count++] = (Token){TOKEN_OR, strdup("||")}; p += 2; continue;
        }
        if (strncmp(p, "&&", 2) == 0) {
            tokens[token_count++] = (Token){TOKEN_AND, strdup("&&")}; p += 2; continue;
        }
        if (strncmp(p, ">>", 2) == 0) {
            tokens[token_count++] = (Token){TOKEN_REDIRECT_APPEND, strdup(">>")}; p += 2; continue;
        }
        if (*p == '|') { tokens[token_count++] = (Token){TOKEN_PIPE, strdup("|")}; ++p; continue; }
        if (*p == '>') { tokens[token_count++] = (Token){TOKEN_REDIRECT_OUT, strdup(">")}; ++p; continue; }
        if (*p == '<') { tokens[token_count++] = (Token){TOKEN_REDIRECT_IN, strdup("<")}; ++p; continue; }
        if (*p == '&') { tokens[token_count++] = (Token){TOKEN_BG, strdup("&")}; ++p; continue; }
        if (*p == ';') { tokens[token_count++] = (Token){TOKEN_SEMICOLON, strdup(";")}; ++p; continue; }
        if (*p == '(') { tokens[token_count++] = (Token){TOKEN_LPAREN, strdup("(")}; ++p; continue; }
        if (*p == ')') { tokens[token_count++] = (Token){TOKEN_RPAREN, strdup(")")}; ++p; continue; }
        char *start; size_t len; char quote = 0;
        if (*p == '\'' || *p == '"') {
            quote = *p++;
            start = p;
            while (*p && *p != quote) p++;
            len = p - start;
            if (*p == quote) p++;
        } else {
            start = p;
            while (*p && !isspace((unsigned char)*p) &&
                   !strchr("|><&;()", *p)) p++;
            len = p - start;
        }
        tokens[token_count].value = malloc(len + 1);
        memcpy(tokens[token_count].value, start, len);
        tokens[token_count].value[len] = '\0';
        tokens[token_count++].type = TOKEN_WORD;
    }
    if (token_count < MAX_TOKENS) {
        tokens[token_count].type   = TOKEN_END;
        tokens[token_count].value  = strdup("");
    }
}

Token peek_token(void) {
    if (current_token < token_count) return tokens[current_token];
    return tokens[token_count];
}
Token next_token(void) {
    if (current_token < token_count) return tokens[current_token++];
    return tokens[token_count];
}
Node *parse_command(void) {
    Node *cmd = parse_conditional();
    Token t = peek_token();
    if (t.type == TOKEN_SEMICOLON || t.type == TOKEN_BG) {
        Node *seq = malloc(sizeof(Node));
        seq->type = (t.type == TOKEN_SEMICOLON) ? NODE_SEQ : NODE_BG;
        seq->data.binary.left = cmd; next_token();
        seq->data.binary.right = parse_command();
        return seq;
    }
    return cmd;
}
Node *parse_conditional(void) {
    Node *left = parse_pipeline();
    while (1) {
        Token t = peek_token();
        if (t.type != TOKEN_AND && t.type != TOKEN_OR) break;
        next_token();
        Node *right = parse_pipeline();
        Node *n = malloc(sizeof(Node));
        n->type = (t.type == TOKEN_AND) ? NODE_AND : NODE_OR;
        n->data.binary.left = left;
        n->data.binary.right = right;
        left = n;
    }
    return left;
}
Node *parse_pipeline(void) {
    Node *cmd = parse_simple();
    if (peek_token().type == TOKEN_PIPE) {
        Node *p = malloc(sizeof(Node));
        p->type = NODE_PIPELINE;
        int cnt = 1;
        Node **arr = malloc(sizeof(Node *) * (cnt + 1));
        arr[0] = cmd;
        while (peek_token().type == TOKEN_PIPE) {
            next_token();
            Node *nxt = parse_simple();
            if (!nxt) break;
            arr = realloc(arr, sizeof(Node *) * (++cnt + 1));
            arr[cnt - 1] = nxt;
        }
        arr[cnt] = NULL;
        p->data.pipeline.commands = arr;
        p->data.pipeline.count   = cnt;
        return p;
    }
    return cmd;
}
Node *parse_simple(void) {
    if (peek_token().type == TOKEN_LPAREN) return parse_subshell();
    if (peek_token().type != TOKEN_WORD) return NULL;
    Node *s = malloc(sizeof(Node));
    s->type = NODE_SIMPLE;
    int argc = 0;
    char **args = malloc(sizeof(char *));
    while (peek_token().type == TOKEN_WORD) {
        Token w = next_token();
        args = realloc(args, sizeof(char *) * (argc + 1));
        args[argc++] = strdup(w.value);
    }
    args = realloc(args, sizeof(char *) * (argc + 1));
    args[argc] = NULL;
    s->data.simple.args = args;
    s->data.simple.argc = argc;

    Token t = peek_token();
    if (t.type == TOKEN_REDIRECT_IN || t.type == TOKEN_REDIRECT_OUT || t.type == TOKEN_REDIRECT_APPEND) {
        Node *r = malloc(sizeof(Node));
        r->type = NODE_REDIRECT;
        r->data.redirect.cmd = s;
        r->data.redirect.input_file = r->data.redirect.output_file = NULL;
        r->data.redirect.append = 0;
        if (t.type == TOKEN_REDIRECT_IN) {
            next_token(); Token f = next_token();
            if (f.type == TOKEN_WORD) r->data.redirect.input_file = strdup(f.value);
        } else {
            next_token(); Token f = next_token();
            if (f.type == TOKEN_WORD) {
                r->data.redirect.output_file = strdup(f.value);
                r->data.redirect.append = (t.type == TOKEN_REDIRECT_APPEND);
            }
        }
        return r;
    }
    return s;
}
Node *parse_subshell(void) {
    if (peek_token().type != TOKEN_LPAREN) return NULL;
    next_token();
    Node *s = malloc(sizeof(Node));
    s->type = NODE_SUBSHELL;
    s->data.subshell.cmd = parse_command();
    if (peek_token().type != TOKEN_RPAREN) { free_node(s); return NULL; }
    next_token();
    return s;
}
void free_node(Node *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_SIMPLE:
            for (int i = 0; i < n->data.simple.argc; i++) free(n->data.simple.args[i]);
            free(n->data.simple.args); break;
        case NODE_PIPELINE:
            for (int i = 0; i < n->data.pipeline.count; i++) free_node(n->data.pipeline.commands[i]);
            free(n->data.pipeline.commands); break;
        case NODE_REDIRECT:
            free_node(n->data.redirect.cmd);
            free(n->data.redirect.input_file); free(n->data.redirect.output_file); break;
        case NODE_AND: case NODE_OR: case NODE_SEQ: case NODE_BG:
            free_node(n->data.binary.left); free_node(n->data.binary.right); break;
        case NODE_SUBSHELL:
            free_node(n->data.subshell.cmd); break;
    }
    free(n);
}
void free_tokens(void) {
    for (int i = 0; i <= token_count; i++) free(tokens[i].value);
    token_count = current_token = 0;
}

int execute_node(Node *node, int is_background) {
    if (!node) return 1;
    switch (node->type) {
        case NODE_SIMPLE:   return execute_simple(node->data.simple.args, is_background);
        case NODE_PIPELINE: return execute_pipeline(node->data.pipeline.commands, node->data.pipeline.count, is_background);
        case NODE_REDIRECT: {
            int saved_in = -1, saved_out = -1, status = 1;
            if (node->data.redirect.input_file) {
                saved_in = dup(STDIN_FILENO);
                int fd = open(node->data.redirect.input_file, O_RDONLY);
                if (fd == -1) { perror(node->data.redirect.input_file); goto redir_done; }
                dup2(fd, STDIN_FILENO); close(fd);
            }
            if (node->data.redirect.output_file) {
                saved_out = dup(STDOUT_FILENO);
                int flags = O_CREAT | O_WRONLY;
                flags |= node->data.redirect.append ? O_APPEND : O_TRUNC;
                int fd = open(node->data.redirect.output_file, flags, 0644);
                if (fd == -1) { perror(node->data.redirect.output_file); goto redir_done; }
                dup2(fd, STDOUT_FILENO); close(fd);
            }
            status = execute_node(node->data.redirect.cmd, is_background);
          redir_done:
            if (saved_in  != -1) { dup2(saved_in, STDIN_FILENO);  close(saved_in);  }
            if (saved_out != -1) { dup2(saved_out, STDOUT_FILENO); close(saved_out); }
            return status;
        }
        case NODE_AND:{
            int st = execute_node(node->data.binary.left, 0);
            DBG("[OR] left=%d → %s\n", st, st ? "execute right" : "skip right");
            return st == 0 ? execute_node(node->data.binary.right, is_background) : st;
        }
        case NODE_OR:{
            int st = execute_node(node->data.binary.left, 0);
            DBG("[OR] left=%d → %s\n", st, st ? "execute right" : "skip right");
            return st != 0 ? execute_node(node->data.binary.right, is_background) : 0;
        }
        case NODE_SEQ:
            execute_node(node->data.binary.left, 0);
            return node->data.binary.right ? execute_node(node->data.binary.right, 0) : 0;
        case NODE_BG:
            return execute_node(node->data.binary.left, 1);
        case NODE_SUBSHELL:{
            sigset_t oldset, newset;
            sigemptyset(&newset); sigaddset(&newset, SIGCHLD);
            sigprocmask(SIG_BLOCK, &newset, &oldset);
            pid_t pid = fork();
            if (pid == 0) { // ребенок
                sigprocmask(SIG_SETMASK, &oldset, NULL);
                exit(execute_node(node->data.subshell.cmd, is_background));
            }
            int status = 1;
            if (pid > 0) status = wait_status(pid);
            else perror("fork");
            sigprocmask(SIG_SETMASK, &oldset, NULL);
            return status;
        }
        default: return 1;
    }
}

int execute_simple(char **args, int is_background) {
    if (!args || !args[0]) return 1;
    if (is_builtin(args[0])) return execute_builtin(args);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid > 0) { // родитель
        DBG("[fork] %d -> %s\n", (int)pid, args[0]);
        if (is_background) printf("[bg] %d\n", (int)pid);
        else return wait_status(pid);
        return 0;
    }
    // сын
    if (!is_background) signal(SIGINT, SIG_DFL);
    if (is_background) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd != -1) { dup2(fd, STDIN_FILENO); close(fd); }
        signal(SIGINT, SIG_IGN);
    }
    execvp(args[0], args);
    perror(args[0]);
    exit(127);
}

int execute_pipeline(Node **commands, int count, int is_background) {
    if (count <= 0 || !commands) return 1;

    int pipes[count - 1][2];
    pid_t last_pid = -1;
    sigset_t oldset, newset;

    sigemptyset(&newset); sigaddset(&newset, SIGCHLD);
    sigprocmask(SIG_BLOCK, &newset, &oldset);

    for (int i = 0; i < count - 1; i++)
        if (pipe(pipes[i]) == -1) {
            perror("pipe"); goto cleanup;
        }

    for (int i = 0; i < count; i++) {
        if (commands[i]->type != NODE_SIMPLE) {
            fprintf(stderr, "pipeline: internal error (not simple)\n");
            goto cleanup;
        }
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); goto cleanup; }

        if (pid == 0) {
            sigprocmask(SIG_SETMASK, &oldset, NULL);
            if (!is_background) signal(SIGINT, SIG_DFL);

            if (i > 0) dup2(pipes[i - 1][0], STDIN_FILENO);
            if (i < count - 1) dup2(pipes[i][1], STDOUT_FILENO);
            for (int j = 0; j < count - 1; j++) {
                close(pipes[j][0]); close(pipes[j][1]);
            }
            if (is_background && i == 0) {
                int fd = open("/dev/null", O_RDONLY);
                if (fd != -1) { dup2(fd, STDIN_FILENO); close(fd); }
                signal(SIGINT, SIG_IGN);
            }
            char **args = commands[i]->data.simple.args;
            execvp(args[0], args);
            perror(args[0]);
            exit(127);
        }
        // родитель
        DBG("[fork] %d -> %s\n", (int)pid, commands[i]->data.simple.args[0]);
        last_pid = pid;
        if (i > 0) { close(pipes[i - 1][0]); close(pipes[i - 1][1]); }
    }
    if (count > 1) { close(pipes[count - 2][0]); close(pipes[count - 2][1]); }

    int status = 1;
    if (last_pid > 0) status = wait_status(last_pid);

    if (is_background && last_pid > 0) printf("[bg] %d\n", (int)last_pid);

    sigprocmask(SIG_SETMASK, &oldset, NULL);
    return status;

cleanup:
    for (int j = 0; j < count - 1; j++) { close(pipes[j][0]); close(pipes[j][1]); }
    sigprocmask(SIG_SETMASK, &oldset, NULL); return 1;
}

int is_builtin(const char *cmd) {
    return strcmp(cmd, "cd") == 0 || strcmp(cmd, "exit") == 0 ||
           strcmp(cmd, "true") == 0 || strcmp(cmd, "false") == 0;
}
int execute_builtin(char **args) {
    if (strcmp(args[0], "cd") == 0)    return builtin_cd(args);
    if (strcmp(args[0], "exit") == 0)  return builtin_exit(args);
    if (strcmp(args[0], "true") == 0)  return 0;
    if (strcmp(args[0], "false") == 0) return 1;
    return 1;
}
int builtin_cd(char **args) {
    const char *dir = args[1] ? args[1] : getenv("HOME");
    if (!dir) { fprintf(stderr, "cd: HOME not set\n"); return 1; }
    if (chdir(dir) == -1) { perror(dir); return 1; }
    free(current_dir); current_dir = getcwd(NULL, 0);
    return 0;
}
int builtin_exit(char **args) {
    exit(args[1] ? atoi(args[1]) : 0);
}