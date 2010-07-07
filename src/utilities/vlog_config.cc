/* Copyright 2008 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "vlog.hh"

#include <boost/ptr_container/ptr_vector.hpp>
#include <boost/foreach.hpp>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "command-line.hh"
#include "vlog-socket.hh"

#define NOT_REACHED() abort()
#define NO_RETURN __attribute__((__noreturn__))

using namespace std;
using namespace vigil;

static void fatal(const char *format, ...) NO_RETURN;

static void
fatal(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    putc('\n', stderr);
    exit(1);
}

void
usage(char *prog_name, int exit_code)
{
    printf("Usage: %s [TARGET] [ACTION...]\n"
           "Targets:\n"
           "  -a, --all            Apply to all targets (default)\n"
           "  -t, --target=TARGET  Specify target program, as a pid or an\n"
           "                       absolute path to a Unix domain socket\n"
           "Actions:\n"
           "  -l, --list         List current settings\n"
           "  -s, --set=MODULE:FACILITY:LEVEL\n"
           "        Set MODULE and FACILITY log level to LEVEL\n"
           "        MODULE may be any valid module name or 'ANY'\n"
           "        FACILITY may be 'syslog' or 'console' or 'ANY'\n"
           "        LEVEL may be 'emer', 'err', 'warn', or 'dbg'\n"
           "  -h, --help         Print this helpful information\n",
           prog_name);
    exit(exit_code);
}

static std::string
transact(Vlog_client_socket& socket, const char* request, bool& ok)
{
    int error;
    std::string reply = socket.transact(request, error);
    if (error) {
        fprintf(stderr, "%s: transaction error: %s\n",
                socket.target().c_str(), strerror(error));
        reply = "";
        ok = false;
    }
    return reply;
}

static void
transact_ack(Vlog_client_socket& socket, const char* request, bool& ok)
{
    int error;
    std::string reply = socket.transact(request, error);
    if (error) {
        fprintf(stderr, "%s: transaction error: %s\n",
                socket.target().c_str(), strerror(error));
        ok = false;
    } else if (reply != "ack") {
        fprintf(stderr, "Received unexpected reply from %s: %s\n",
                socket.target().c_str(), reply.c_str());
        ok = false;
    }
}

static void
add_target(boost::ptr_vector<Vlog_client_socket>& targets,
           const std::string& path, bool& ok)
{
    std::auto_ptr<Vlog_client_socket> socket(new Vlog_client_socket);
    int error = socket->connect(path.c_str());
    if (error) {
        fprintf(stderr, "Error connecting to \"%s\": %s\n",
                path.c_str(), strerror(error));
        ok = false;
    } else {
        targets.push_back(socket);
    }
}

static void
add_all_targets(boost::ptr_vector<Vlog_client_socket>& targets, bool& ok)
{
    DIR* directory = opendir("/tmp");
    if (!directory) {
        fprintf(stderr, "/tmp: opendir: %s\n", strerror(errno));
    }

    while (struct dirent* de = readdir(directory)) {
        if (!strncmp(de->d_name, "vlogs.", 5)) {
            add_target(targets, std::string("/tmp/") + de->d_name, ok);
        }
    }

    closedir(directory);
}

int main(int argc, char *argv[])
{
    /* Determine targets. */
    bool ok = true;
    int n_actions = 0;
    boost::ptr_vector<Vlog_client_socket> targets;
    for (;;) {
        static const struct option long_options[] = {
            /* Target options must come first. */
            {"all", no_argument, NULL, 'a'},
            {"target", required_argument, NULL, 't'},
            {"help", no_argument, NULL, 'h'},

            /* Action options come afterward. */
            {"list", no_argument, NULL, 'l'},
            {"set", required_argument, NULL, 's'},
            {0, 0, 0, 0},
        };
        static const std::string short_options
            = long_options_to_short_options(long_options);
        int option = getopt_long(argc, argv, short_options.c_str(),
                                 long_options, NULL);
        if (option == -1) {
            break;
        }
        if (!strchr("ath", option) && targets.empty()) {
            fatal("no targets specified (use --help for help)");
        } else {
            ++n_actions;
        }
        switch (option) {
        case 'a':
            add_all_targets(targets, ok);
            break;

        case 't':
            add_target(targets, optarg, ok);
            break;

        case 'l':
            BOOST_FOREACH (Vlog_client_socket& s, targets) {
                printf("%s:\n", s.target().c_str());
                fputs(transact(s, "list", ok).c_str(), stdout);
            }
            break;

        case 's':
            BOOST_FOREACH (Vlog_client_socket& s, targets) {
                transact_ack(s, (std::string("set ") + optarg).c_str(), ok);
            }
            break;

        case 'h':
            usage(argv[0], EXIT_SUCCESS);
            break;

        default:
            NOT_REACHED();
        }
    }
    if (!n_actions) {
        fprintf(stderr,
                "warning: no actions specified (use --help for help)\n");
    }
    exit(ok ? 0 : 1);
}
