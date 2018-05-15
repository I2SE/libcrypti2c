/*
 * Copyright (C) 2018 I2SE GmbH
 *
 * This file is part of libcryptoauth.
 *
 * libcryptoauth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libcryptoauth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libcryptoauth.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>
#include <getopt.h>
#include <errno.h>

#include "config.h"
#include "libcryptoauth.h"

#define __stringify_1(x...) #x
#define __stringify(x...)   __stringify_1(x)

#define NO_EXIT -1
#define OPTIONS_DEFAULT_DEVICE "/dev/i2c-0"
#define OPTIONS_DEFAULT_ADDRESS 0x60

/* command line options */
const struct option long_options[] = {
    { "address",            required_argument, 0, 'a' },
    { "file",               required_argument, 0, 'f' },
    { "device",             required_argument, 0, 'd' },
    { "encrypt",            no_argument,       0, 'e' },
	{ "public-key",         required_argument, 0, 'p' },
    { "verbose",            no_argument,       0, 'v' },
    { "version",            no_argument,       0, 'V' },
    { "help",               no_argument,       0, 'h' },
    {} /* stop condition for iterator */
};

/* descriptions for the command line options */
const char *long_options_descs[] = {
    "use given I2C address (default: " __stringify(OPTIONS_DEFAULT_ADDRESS) ")",
    "use given XML file with memory configuration (no default)",
    "I2C device to use (default: " OPTIONS_DEFAULT_DEVICE ")",
    "encrypt key write commands (default: no)",
	"public key with uncompressed point tag (default: none)",
    "switch on verbose output (default: off)",
    "print version and exit",
    "print this usage and exit",
    NULL /* stop condition for iterator */
};

int usage(const char *p, int exitcode)
{
    const char **desc = long_options_descs;
    const struct option *op = long_options;

    fprintf(stderr,
            "%s (%s) -- Utility for burning the configuration, data and OTP zones of an Atmel crypto chip\n\n"
            "Usage: %s [<options>] <command> [<parameter>...]\n\n"
            "Commands:\n"
            "\tprint-serial            print crypto chip's serial number\n"
            "\n"
            "\tprint-state             print crypto chip's current state, i.e. one of the strings:\n"
            "\t                        FACTORY, INITIALIZED, PERSONALIZED or UNKNOWN\n"
            "\n"
            "\twrite-key <slot>        write a single slot\n"
            "\n"
            "\twrite-keys              write all slots as defined in XML configuration\n"
            "\n"
            "\tverify-key <slot>       verify a single slot using slot information provided in\n"
            "\t                        XML configuration file and print OK or FAILED\n"
            "\n"
            "\twrite-config            only write configuration zone\n"
            "\n"
            "\tlock-config             lock configuration zone\n"
            "\n"
            "\totp                     write OTP zone lock it\n"
            "\n"
            "\tpersonalize             write configuration, OTP and data zones and lock all zones\n"
            "\n"
            "Parameters:\n"
            "\t<slot>                  integer in the range 0-15\n"
            "\n"
            "Options:\n",
            p, PACKAGE_STRING, p);

    while (op->name && desc) {
        fprintf(stderr, "\t-%c, --%-12s\t%s\n", op->val, op->name, *desc);
        op++; desc++;
    }

    fprintf(stderr, "\n");
    if (exitcode != NO_EXIT)
        exit(exitcode);

    return exitcode;
}

enum cmds {
    CMD_PRINT_SERIAL,
    CMD_PRINT_STATE,
    CMD_WRITE_KEY,
    CMD_WRITE_KEYS,
    CMD_VERIFY_KEY,
    CMD_WRITE_CONFIG,
    CMD_LOCK_CONFIG,
    CMD_OTP,
    CMD_PERSONALIZE,
    /* keep last */
    CMD_MAX
};

struct command {
    const char *cmd;
    int args;
    bool needs_xmlfile;
};

const struct command commands[] = {
    { "print-serial", 0, false },
    { "print-state",  0, false },
    { "write-key",    1, true  },
    { "write-keys",   0, true  },
    { "verify-key",   1, true  },
    { "write-config", 0, true  },
    { "lock-config",  0, true  },
    { "otp",          0, true  },
    { "personalize",  0, true  },
};

int find_cmd(const char *command)
{
    int i;

    for (i = 0; i < CMD_MAX; i++)
        if (strcasecmp(commands[i].cmd, command) == 0)
            break;

    return i;
}

int write_single_slot(int fd, const char *xmlfile, int slot, bool encrypt, struct lca_octet_buffer config)
{
    uint16_t slot_config, key_config;

    if (!lca_get_slot_config(slot, config, &slot_config))
        return -1;

    if (!lca_get_key_config(slot, config, &key_config))
        return -2;

    return lca_write_key(fd, slot, encrypt, xmlfile, slot_config, key_config);
}

/* check whether there is garbage at the string end */
int safe_strtol(const char *nptr, int base, int *value)
{
	long int v;
	char *endptr;

	v = strtol(nptr, &endptr, base);
	if (*endptr)
		return -1;

	*value = v;
	return 0;
}

int main(int argc, char *argv[])
{
    int rv = EXIT_FAILURE;
    char *xmlfile = NULL, *device = OPTIONS_DEFAULT_DEVICE;
    char *public_key = NULL;
    int address = OPTIONS_DEFAULT_ADDRESS;
    bool verbose = false;
    bool encrypt = false;
    int fd = -1;
    int cmd;

    while (1) {
        int c = getopt_long(argc, argv, "a:d:f:p:vVh", long_options, NULL);

        /* detect the end of the options */
        if (c == -1) break;

        switch (c) {
            case 'a':
                if (safe_strtol(optarg, 0, &address)) {
                    fprintf(stderr, "ERROR: parsing I2C address '%s'.", optarg);
                    return rv;
                }
                break;
            case 'd':
                device = optarg;
                break;
            case 'e':
                encrypt = true;
                break;
            case 'f':
                xmlfile = optarg;
                break;
            case 'p':
                public_key = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'V':
                printf("%s (%s)\n", argv[0], PACKAGE_STRING);
                exit(EXIT_SUCCESS);
            case '?':
            case 'h':
                rv = EXIT_SUCCESS;
                /* fall-through */
            default:
                usage(argv[0], rv);
        }
    }

    /* adjust argc/argv to point to command and parameters after options */
    argc -= optind;
    argv += optind;

    /* we require at least the command (check this first to avoid null ptr deref
     * in second check) and a valid command at all */
    if (argc < 1 ||
        (cmd = find_cmd(argv[0])) == CMD_MAX)
        usage(program_invocation_short_name, rv);

    /* check parameter count for given command */
    if (commands[cmd].args + 1 != argc)
        usage(program_invocation_short_name, rv);

    /* check if command requires xml file */
    if (!xmlfile && commands[cmd].needs_xmlfile) {
        fprintf(stderr, "ERROR: command requires an XML configuration file, but none given.\n");
        return EXIT_FAILURE;
    }

    if (public_key) {
        if (strlen(public_key) != 130) {
            fprintf(stderr, "ERROR: ECC public key has invalid length\n");
            return EXIT_FAILURE;
        }
    }

    /* init library and open device */
    lca_init_and_debug(verbose ? LCA_DEBUG : LCA_INFO);
    fd = lca_atmel_setup(device, address);
    if (fd == -1) {
        fprintf(stderr, "ERROR: opening '%s' %m\n", device);
        goto close_out;
    }

    /* run given command */
    switch (cmd) {

    case CMD_PRINT_SERIAL: {
        struct lca_octet_buffer serial;

        serial = lca_get_serial_num(fd);

        if (serial.ptr) {
            int i;

            printf("%02X", serial.ptr[0]);
            for (i = 1; i < serial.len; i++)
                printf(":%02X", serial.ptr[i]);

            printf("\n");
            rv = 0;
            lca_free_octet_buffer(serial);
        }
    }
        break;

    case CMD_PRINT_STATE:
        rv = lca_get_device_state(fd);

        switch (rv) {
            case STATE_FACTORY:
                printf("FACTORY\n");
                break;
            case STATE_INITIALIZED:
                printf("INITIALIZED\n");
                break;
            case STATE_PERSONALIZED:
                printf("PERSONALIZED\n");
                break;
            case STATE_INVALID:
            	printf("INVALID\n");
            	break;
            default:
                printf("UNKNOWN\n");
                break;
        }

        rv = 0;
        break;


    case CMD_WRITE_KEY: {
        struct lca_octet_buffer config;
        int slot;

        if (safe_strtol(argv[1], 0, &slot)) {
            fprintf(stderr, "ERROR: parsing slot parameter.\n");
            goto idle_out;
        }

        if (lca_config2bin(xmlfile, &config)) {
            fprintf(stderr, "ERROR: parsing XML configuration zone.\n");
            goto idle_out;
        }

        rv = write_single_slot(fd, xmlfile, slot, encrypt, config);

        lca_free_octet_buffer(config);

    }
        break;

    case CMD_WRITE_KEYS: {
        struct lca_octet_buffer config;
        int slot;

        if (lca_config2bin(xmlfile, &config)) {
            fprintf(stderr, "ERROR: parsing XML configuration zone.\n");
            goto idle_out;
        }

        rv = 0;

        for (slot = 0; slot < 15; slot++) {
            rv |= write_single_slot(fd, xmlfile, slot, encrypt, config);
        }

        lca_free_octet_buffer(config);

    }
        break;

    case CMD_VERIFY_KEY: {
        struct lca_octet_buffer config;
        struct lca_octet_buffer pub_key = { 0, 0 };
        uint16_t slot_config, key_config;
        int slot, i;
        char *pos = public_key;

        if (public_key) {
            pub_key = lca_make_buffer (65);

            for (i = 0; i < pub_key.len; i++) {
                sscanf(pos, "%2hhx", &pub_key.ptr[i]);
                pos += 2;
            }
        }

        if (safe_strtol(argv[1], 0, &slot)) {
            fprintf(stderr, "ERROR: parsing slot parameter.\n");
            goto idle_out;
        }

        if (lca_config2bin(xmlfile, &config)) {
            fprintf(stderr, "ERROR: parsing XML configuration zone.\n");
            goto idle_out;
        }

        lca_get_slot_config(slot, config, &slot_config);
        lca_get_key_config(slot, config, &key_config);

        rv = lca_verify_key(fd, slot, xmlfile, slot_config, key_config, pub_key);
        printf(rv ? "FAILED\n" : "OK\n");
        lca_free_octet_buffer(config);
    }
        break;

    case CMD_WRITE_CONFIG: {
        struct lca_octet_buffer config, response;
        int i;

        if (lca_config2bin(xmlfile, &config)) {
            fprintf(stderr, "ERROR: parsing XML configuration zone.\n");
            goto idle_out;
        }

        rv = lca_burn_config_zone(fd, config);
        if (rv) {
            fprintf(stderr, "ERROR: writing configuration zone.\n");
            lca_free_octet_buffer(config);
            goto idle_out;
        }

        lca_idle(fd);

        /* we need to wait until we can read back correct data */
        sleep(1);

        lca_wakeup(fd);

        printf("\n"); /* FIXME */

        response = get_config_zone(fd);
        if (response.ptr == NULL) {
            fprintf(stderr, "ERROR: Unable to get configuration.\n");
            lca_free_octet_buffer(config);
            goto idle_out;
        }

        printf("Verify configuration:");

        for (i = 0; i < response.len; i++) {
            if (i % 4 == 0)
                printf("\n%04u : ", i);

            if (config.ptr[i] == response.ptr[i]) {
                printf("== ");
            } else {
                printf("%02X ", response.ptr[i]);

                if (lca_is_config_offset_writable(i))
                    rv = -2;
            }
        }

        printf("\n"); /* FIXME */

        if (rv)
            fprintf(stderr, "ERROR: Configuration mismatch\n");

        lca_free_octet_buffer(config);
        lca_free_octet_buffer(response);
    }
        break;

    case CMD_LOCK_CONFIG: {
        struct lca_octet_buffer config;

        if (lca_config2bin(xmlfile, &config)) {
            fprintf(stderr, "ERROR: parsing XML configuration zone.\n");
            goto idle_out;
        }

        rv = lca_lock_config_zone(fd, config);
        if (rv) {
            fprintf(stderr, "ERROR: Locking configuration zone.\n");
        }

        lca_free_octet_buffer(config);
    }
        break;

    case CMD_OTP: {

        rv = lca_burn_and_lock_otp_zone (fd, xmlfile);
        if (rv) {
            fprintf(stderr, "ERROR: Writing and locking OTP zone.\n");
        }

    }
        break;

    case CMD_PERSONALIZE: {
        struct lca_octet_buffer response;
        int i;

        rv = personalize(fd, xmlfile);
        if (rv) {
            fprintf(stderr, "ERROR: Failed to personalize the device.\n");
            goto idle_out;
        }

        lca_idle(fd);
        sleep (1);
        lca_wakeup(fd);

        printf("\n"); /* FIXME */

        response = get_otp_zone (fd);
        if (response.ptr == NULL) {
            fprintf(stderr, "ERROR: Failed to get OTP zone.\n");
            goto idle_out;
        }

        printf("Verify OTP:");

        for (i = 0; i < response.len; i++) {
            if (i % 4 == 0)
                printf("\n%04u : ", i);

            printf ("%02X ", response.ptr[i]);
        }

        lca_free_octet_buffer(response);

        printf("\n"); /* FIXME */

    }
        break;

    default:
        /* this cannot happen since we checked above */
        usage(program_invocation_short_name, NO_EXIT);
    }

idle_out:
    if (fd != -1)
        lca_idle(fd);

close_out:
    if (fd != -1)
        close(fd);

    return rv ? EXIT_FAILURE : EXIT_SUCCESS;
}
