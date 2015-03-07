import os

TIMEOUT = 10
SEARCH_WINDOW_SIZE = 100

# A stab at a class wrapping up the above.

class Remote:

    def __init__(self, child, hostname, prompt="\[root@[^ ]+ [^\]]+\]# "):
        self.child = child
        self.hostname = hostname
        self.prompt = prompt
        self.logging = False

    def run(self, command, timeout=TIMEOUT):
        # "swantest" just, sometimes, prints the prompt/command to the
        # console.  An alternative would be to use fab.tee.Tee so that
        # everything is written to both the file, and stdout.
        if self.logging:
            # The re.replace() strips the \ from \[.  The result is
            # pretty but misleading.
            print(("%s: %s" % (self.prompt.replace("\\", ""), command)))
        self.child.sendline(command)
        self.child.expect(self.prompt, timeout=timeout, searchwindowsize=SEARCH_WINDOW_SIZE)

    def cd(self, directory):
        self.prompt = "\[root@%s %s\]# " % (self.hostname, os.path.basename(directory))
        self.run("cd %s" % directory)
        return self.prompt

    # Read the contents of a local file and run each line.  assumes
    # that all lines contain simple shell commands.
    #
    # For anything more complicated, use run() above to run the script
    # remotely.
    def read_file_run(self, filename, timeout=TIMEOUT):
        f_cmds = None
        try:
            f_cmds = open(filename, "r")
            for line in f_cmds:
                line = line.strip()    
                # We need the lines with # for the cut --- tuc
                # sections if line and not line[0] == '#':
                if line:
                    self.run(line, timeout)
        finally:
            if f_cmds:
                f_cmds.close

    # Capture and return last command's exit status.
    #
    # Unfortunately, as side effect, this eats the exit code.  It
    # would be nice if run, above, directly captured the exit code.
    def exit_status(self):
        self.child.sendline("echo status=$?")
        self.child.expect('status=([0-9]+)\s*' + self.prompt, timeout=TIMEOUT)
        status = int(self.child.match.group(1))
        # child.sendline("(exit %s)" % status)
        return status

    def exit_if_error(self):
        status = self.exit_status()
        if status:
            # anything non-zero, pass it out
            sys.exit(status)
