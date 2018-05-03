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
#include <stdbool.h>
#include <strings.h>
#include <getopt.h>
#include <errno.h>

#include "config.h"
#include "libcryptoauth.h"

#define NO_EXIT -1
#define OPTIONS_DEFAULT_DEVICE "/dev/i2c-0"

/* command line options */
const struct option long_options[] = {
    { "file",               required_argument, 0, 'f' },
    { "device",             required_argument, 0, 'd' },
    { "verbose",            no_argument,       0, 'v' },
    { "version",            no_argument,       0, 'V' },
    { "help",               no_argument,       0, 'h' },
    {} /* stop condition for iterator */
};

/* descriptions for the command line options */
const char *long_options_descs[] = {
    "use given XML file with memory configuration (no default)",
    "I2C device to use (default: " OPTIONS_DEFAULT_DEVICE ")",
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

int write_single_slot(int fd, const char *xmlfile, int slot, struct lca_octet_buffer config)
{
    struct lca_octet_buffer slot_data;
    uint16_t slot_config, key_config;

    lca_get_slot_config(slot, config, &slot_config);
    lca_get_key_config(slot, config, &key_config);

    return lca_write_key(fd, slot, xmlfile, slot_config, key_config);
}

int main(int argc, char *argv[])
{
    int rv = EXIT_FAILURE;
    char *xmlfile, *device = OPTIONS_DEFAULT_DEVICE;
    bool verbose = false;
    int fd = -1;

    while (1) {
        int c = getopt_long(argc, argv, "d:f:vVh", long_options, NULL);

        /* detect the end of the options */
        if (c == -1) break;

        switch (c) {
            case 'd':
                device = optarg;
                break;
            case 'f':
                xmlfile = optarg;
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

    /* we require at least the command (check this first to avoid null ptr deref in next check) */
    if (argc < 1)
        usage(program_invocation_short_name, rv);

    /* these commands need one parameter */
    if (argc == 2 &&
        (strcasecmp(argv[0], "write-key") == 0 ||
         strcasecmp(argv[0], "verify-key") == 0))
        goto cmdline_ok;
    
    /* all others need only command, no parameters */
    if (argc == 1 &&
        !(strcasecmp(argv[0], "write-key") == 0 ||
          strcasecmp(argv[0], "verify-key") == 0))
        goto cmdline_ok;

    /* this exits the program here */
    usage(program_invocation_short_name, rv);

cmdline_ok:
    if (!xmlfile &&
        !(strcasecmp(argv[0], "print-serial") == 0 ||
          strcasecmp(argv[0], "print-state") == 0 ||
          strcasecmp(argv[0], "lock-config") == 0)) {
        fprintf(stderr, "This operation requires an XML configuration file, but none given.\n");
        return EXIT_FAILURE;
    }

    /* init library and open device */
    lca_init_and_debug(verbose ? LCA_DEBUG : LCA_INFO);
    fd = lca_atmel_setup(device, 0x60);
    if (fd == -1) {
        fprintf(stderr, "Error opening '%s': %m\n", device);
        goto close_out;
    }

    /* run given command */
    if (strcasecmp(argv[0], "print-serial") == 0) {
        struct lca_octet_buffer serial;

        serial = lca_get_serial_num(fd);

        if (serial.ptr) {
            int i;

            printf("%02X", serial.ptr[0]);
            for (i = 1; i < serial.len; i++)
                printf(":%02X", serial.ptr[i]);

            printf("\n");
            rv = 0;
        }

    } else if (strcasecmp(argv[0], "print-state") == 0) {
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
            default:
                printf("UNKNOWN\n");
                break;
        }

        rv = 0;

    } else if (strcasecmp(argv[0], "write-key") == 0) {
        struct lca_octet_buffer config;
        int slot;

        slot = atoi(argv[1]);

        if (lca_config2bin(xmlfile, &config) == 0) {
            fprintf(stderr, "Error parsing XML configuration zone.\n");
            goto idle_out;
        }

        rv = write_single_slot(fd, xmlfile, slot, config);

    } else if (strcasecmp(argv[0], "write-keys") == 0) {
        struct lca_octet_buffer config;
        int slot;

        if (lca_config2bin(xmlfile, &config) == 0) {
            fprintf(stderr, "Error parsing XML configuration zone.\n");
            goto idle_out;
        }

        for (slot = 0; slot < 15; slot++) {
            rv |= write_single_slot(fd, xmlfile, slot, config);
        }

    } else if (strcasecmp(argv[0], "verify-key") == 0) {
        struct lca_octet_buffer config;
        int slot;

        slot = atoi(argv[1]);

        if (lca_config2bin(xmlfile, &config) == 0) {
            fprintf(stderr, "Error parsing XML configuration zone.\n");
            goto idle_out;
        }

        rv = 0; /* TODO */

    } else if (strcasecmp(argv[0], "write-config") == 0) {
        struct lca_octet_buffer config, result, response;
        int i;

        if (lca_config2bin(xmlfile, &config) == 0) {
            fprintf(stderr, "Error parsing XML configuration zone.\n");
            goto idle_out;
        }

        rv = lca_burn_config_zone(fd, result);
        if (rv) {
            fprintf(stderr, "Error writing configuration zone.\n");
            goto idle_out;
        }

        lca_idle(fd);

        /* we need to wait until we can read back correct data */
        sleep(1);

        lca_wakeup(fd);

        printf("\n"); /* FIXME */

        response = get_config_zone(fd);
        if (response.ptr == NULL) {
            fprintf(stderr, "Unable to get configuration.\n");
            goto idle_out;
        }

        printf("Verify configuration:");

        for (i = 0; i < response.len; i++) {
            if (i % 4 == 0)
                printf("\n%04u : ", i);

            if (result.ptr[i] == response.ptr[i])
                printf("== ");
            else
                printf("%02X ", response.ptr[i]);
        }

        lca_free_octet_buffer(response);

        printf("\n"); /* FIXME */

    } else if (strcasecmp(argv[0], "lock-config") == 0) {
        struct lca_octet_buffer result;

        rv = lca_lock_config_zone(fd, result);

    } else if (strcasecmp(argv[0], "personalize") == 0) {
        struct lca_octet_buffer response;
        int i;

        rv = personalize(fd, xmlfile);
        if (rv) {
            fprintf(stderr, "Failed to personalize the device.\n");
            goto idle_out;
        }

        lca_idle(fd);
        sleep (1);
        lca_wakeup(fd);

        printf("\n"); /* FIXME */

        response = get_otp_zone (fd);
        if (response.ptr == NULL) {
            fprintf(stderr, "Failed to get OTP zone.\n");
            goto idle_out;
        }

        printf("Verify OTP:");

        for (i = 0; i < response.len; i++) {
            if (i % 4 == 0)
                printf("\n%04u : ", i);

            printf ("%02X ", response.ptr[i]);
        }

        lca_free_octet_buffer(response);

        rv = 0;

        printf("\n"); /* FIXME */

    } else {
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
