/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * TODO Name, Group
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include<string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static int shell_cd(word_t *dir)
{
    if (!dir)
        return EXIT_SUCCESS;
    
    int ret = chdir(dir->string);
    /* TODO execute cd */
    if (ret < 0)
        ret = EXIT_FAILURE;
    return ret;
}

/*
 * @filedes  - file descriptor to be redirected
 * @filename - filename used for redirection
 */
static void do_redirect(int filedes, const char *filename, bool read_flag, bool append)
{
	int ret;
	int fd;
	int flags = 0;

	/* TODO - Redirect filedes into file filename */
	if (read_flag)
            flags = O_RDONLY;
	else{
            flags = O_WRONLY | O_CREAT | O_TRUNC;
    
            if (append)
                    flags = O_WRONLY | O_APPEND | O_CREAT ;
	}

	fd = open(filename, flags, 0644);
	DIE(fd < 0, "open");

	ret = dup2(fd, filedes);
	DIE(ret < 0, "dup2");

	close(fd);
}

bool is_redirected(simple_command_t *s)
{
    return s->in || s->out || s->err;
}

void set_redirects(simple_command_t *s)
{
    char *in;
    char *out;
    char *err;

    if (s->in){
        in = get_word(s->in);
        do_redirect(STDIN_FILENO, in, true, false );
        free(in);
    }
    if (s->out){
        out = get_word(s->out);
        do_redirect(STDOUT_FILENO, out, false, s->io_flags == IO_OUT_APPEND );
        free(out);
        err = get_word(s->err);
        if (s->err && !strcmp(err, out)){
            DIE(dup2(STDOUT_FILENO, STDERR_FILENO) < 0, "dup2");
            return;
        }
            
    }
    if (s->err){
        err = get_word(s->err);
        do_redirect(STDERR_FILENO, err, false, s->io_flags == IO_ERR_APPEND );
    }
}


static void shell_unknown(char *command)
{
    fprintf(stderr, "Execution failed for '%s'\n", command);
    free(command);
    exit( EXIT_FAILURE);
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
    /* TODO execute exit/quit */
    return SHELL_EXIT; /* TODO replace with actual exit code */
}


static bool is_builtin_command(simple_command_t *s)
{
    return (!strcmp(s->verb->string, "exit") || 
        !strcmp(s->verb->string, "quit") ||
        !strcmp(s->verb->string, "cd"));
}


static int builtin_command_executor(simple_command_t *s)
{
    int ret = SHELL_EXIT;
    
    if (!strcmp(s->verb->string, "exit") || 
        !strcmp(s->verb->string, "quit")){
        
        ret = shell_exit();
        return ret;
    }
    // much modularity much incrementations much w0w
    int default_stdin, default_stdout, default_stderr;
    
    default_stdin = dup(STDIN_FILENO);
    default_stdout = dup(STDOUT_FILENO);
    default_stderr = dup(STDERR_FILENO);
    
    if (is_redirected(s))
        set_redirects(s);
    
    if (!strcmp(s->verb->string, "cd")){
        ret = shell_cd(s->params);
    }
    
    // reset defaput stds
    dup2(default_stdin, STDIN_FILENO);
    dup2(default_stdout, STDOUT_FILENO);
    dup2(default_stderr, STDERR_FILENO);
    
    return ret;
}


static int set_var(const char *var, const char *value)
{
    /* TODO - Set the environment variable */
    if (setenv(var, value, 1))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

static char *expand(const char *key)
{
    /* TODO - Return the value of environment variable */
    return getenv(key);
}



/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
    int ret;
    /* TODO sanity checks */
    /* TODO if builtin command, execute the command */
    if (is_builtin_command(s))
        return builtin_command_executor(s);

    /* TODO if variable assignment, execute the assignment and return
        * the exit status
        */
    
    if (s->verb->next_part && !strcmp(s->verb->next_part->string, "=")){
        char *word = get_word(s->verb);
        char *value = calloc(strlen(word) + 1, sizeof(char));
        word_t *cur = s->verb->next_part->next_part;
        while(cur){
            if (cur->expand)
                strcat(value, expand(cur->string));
            else
                strcat(value, cur->string);
            cur = cur->next_part;
        }
        ret = set_var(s->verb->string, value);
        free(value);
        free(word);
        return ret;
            
    }
    /* TODO if external command:
        *   1. fork new process
        *     2c. perform redirections in child
        *     3c. load executable in child
        *   2. wait for child
        *   3. return exit status
        */
        
    pid_t pid, wait_ret;
    int status;
    int nr_of_params;
    /* TODO - Create a process to execute the command */
    pid = fork();
    char** args;
    switch (pid) {
    case -1:	/* error */
            perror("fork");
            return EXIT_FAILURE;

    case 0:		/* child process */
            args = get_argv(s, &nr_of_params);
            
            if (is_redirected(s))
                set_redirects(s);

            char *word = get_word(s->verb);
            if (execvp(word, (char *const *) args) < 0)
                shell_unknown(word);
            free(word);

    default:	/* parent process */
            wait_ret = waitpid(pid, &status, 0);
            DIE(wait_ret < 0, "waitpid");
            if (WIFEXITED(status))
                return WEXITSTATUS(status);
    }
    
    return EXIT_FAILURE; /* TODO replace with actual exit status */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static int do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
    pid_t pid, pid1, wait_ret, wait_ret1;
    int status;

    /* TODO - Create a process to execute the command */

    pid = fork();
    switch (pid) {
    case -1:	/* error */
        perror("fork");
        exit(EXIT_FAILURE);
        break;

    case 0:		/* child process */
        parse_command(cmd1, level + 1, father);
        exit(EXIT_FAILURE);

    default:	/* parent process */
        parse_command(cmd2, level + 1, father);
        //signal(SIGCHLD, SIG_IGN);
        break;
    }

    /* TODO replace with actual exit status */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static int do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
    /* TODO redirect the output of cmd1 to the input of cmd2 */

    pid_t pid, pid1, wait_ret, wait_ret1;
    int status;
    int fd[2];
    int ret;

    /* TODO - Create a process to execute the command */
    pid = fork();
    switch (pid) {
    case -1:	/* error */
        perror("fork");
        exit(EXIT_FAILURE);
        break;

    case 0:		/* child process */
        DIE(pipe(fd) < 0, "err pipe");
        pid1 = fork();
        switch (pid1) {
        case -1:	/* error */
            perror("fork");
            exit(EXIT_FAILURE);
            break;

        case 0:		/* child process */
            DIE(close(fd[WRITE]) < 0,"err close write pipe");
            
            DIE(dup2(fd[READ], STDIN_FILENO) < 0,"err dup read pipe in stdin");
            
            DIE(close(fd[READ]) < 0,"err close read pipe");
            
            exit(parse_command(cmd2, level, father));

                
        default:	/* parent process */
            //printf("niania\n");
            DIE(close(fd[READ]) < 0,"err close read pipe");
            
            DIE(dup2(fd[WRITE], STDOUT_FILENO) < 0,"err dup write pipe in stdout");
            
            DIE(close(fd[WRITE]) < 0,"err close write pipe");
            
            ret = parse_command(cmd1, level, father);
            
            DIE(close(STDOUT_FILENO),"err eof 2 child");
            
            wait_ret = waitpid(pid1, &status, 0);
            
            DIE(wait_ret < 0, "err waitpid");
            
            if (WIFEXITED(status))
                exit(WEXITSTATUS(status));
            exit(EXIT_FAILURE);
        }

            
    default:	/* parent process */
        wait_ret = waitpid(pid, &status, 0);
        DIE(wait_ret < 0, "err waitpid");
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
    }
    
    return EXIT_FAILURE; /* TODO replace with actual exit status */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
    /* TODO sanity checks */
    int ret;

    switch (c->op) {
        
    case OP_NONE:
        /* TODO execute a simple command */
        ret = parse_simple(c->scmd, level, father);
        break;

    case OP_SEQUENTIAL:
        /* TODO execute the commands one after the other */
        parse_command(c->cmd1, level + 1, c);
        ret = parse_command(c->cmd2, level + 1, c);
        break;

    case OP_PARALLEL:
        /* TODO execute the commands simultaneously */
        ret = do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
        break;

    case OP_CONDITIONAL_NZERO:
        /* TODO execute the second command only if the first one
            * returns non zero
            */
        ret = parse_command(c->cmd1, level + 1, c);
        if (ret)
            ret = parse_command(c->cmd2, level + 1, c);
        break;

    case OP_CONDITIONAL_ZERO:
        /* TODO execute the second command only if the first one
            * returns zero
            */
        ret = parse_command(c->cmd1, level + 1, c);
        if (!ret)
            ret = parse_command(c->cmd2, level + 1, c);
        break;

    case OP_PIPE:
        /* TODO redirect the output of the first command to the
            * input of the second
            */
        ret = do_on_pipe(c->cmd1, c->cmd2, level + 1, father);
        break;

    default:
        return SHELL_EXIT;
    }

    return ret; /* TODO replace with actual exit code of command */
}
