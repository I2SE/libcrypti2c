#include <stdlib.h>
#include <argp.h>
#include <assert.h>
#include "../libcryptoauth.h"

const char *argp_program_version =
  "burnutil 0.2";
const char *argp_program_bug_address =
  "<bugs@cryptotronix.com>";

/* Program documentation. */
static char doc[] =
  "Utility for burning the config, data and otp zones";

/* A description of the arguments we accept. */
static char args_doc[] = "BUS";

/* Number of required args */
#define NUM_ARGS 1

/* The options we understand. */
static struct argp_option options[] = {
  {"write_keys",   'a', 0,         0,  "Write all keys" },
  {"write_config", 'c', 0,         0,  "Write config zone" },
  {"file",         'f', "XMLFILE", 0,  "XML Memory configuration file" },
  {"write_key",    'k', "SLOT",    0,  "Write key into slot" },
  {"lock",         'l', 0,         0,  "Locks config zone"},
  {"otp",          'o', 0,         0,  "Write and lock OTP zone" },
  {"personalize",  'p', 0,         0,  "Fully personalizes device"},
  {"quiet",        'q', 0,         0,  "Don't produce any output" },
  {"print_serial", 's', 0,         0,  "Print device serial number" },
  {"print_state",  't', 0,         0,  "Print device state" },
  {"verbose",      'v', 0,         0,  "Produce verbose output" },
  {"verify_key",   'y', "SLOT",    0,  "Verify key" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
    char *args[NUM_ARGS];                /* arg1 & arg2 */
    int quiet;
    int write_config;
    int write_keys;
    int verify_keys;
    int otp;
    int verbose;
    int lock;
	int personalize;
	int print_serial;
	int print_state;
	int slot;
    char *display;
	char *input_file;
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'a':
      arguments->write_keys = 2;
      break;
    case 'c':
      arguments->write_config = 1;
      break;
    case 'f':
      arguments->input_file = arg;
      break;
    case 'k':
      arguments->write_keys = 1;
      arguments->slot = atoi(arg);
      break;
    case 'l':
      arguments->lock = 1;
      break;
    case 'o':
      arguments->otp = 1;
      break;
    case 'p':
      arguments->personalize = 1;
      break;
    case 'q':
      arguments->quiet = 1;
      break;
    case 's':
      arguments->print_serial = 1;
      break;
    case 't':
      arguments->print_state = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      break;
    case 'y':
      arguments->verify_keys = 1;
      arguments->slot = atoi(arg);
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= NUM_ARGS)
        /* Too many arguments. */
        argp_usage (state);

      arguments->args[state->arg_num] = arg;

      break;

    case ARGP_KEY_END:
      if (state->arg_num < NUM_ARGS)
        /* Not enough arguments. */
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };



int
main (int argc, char **argv)
{
  struct arguments arguments;
  struct lca_octet_buffer serial;
  int i, rc = 1;

  /* Default values. */
  memset(&arguments, 0, sizeof(arguments));

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  if ((0 == arguments.print_serial) &&
	  (0 == arguments.print_state) &&
	  (NULL == arguments.input_file))
  {
      printf("Need xml file\n");
      exit (1);
  }

  lca_init_and_debug (arguments.verbose ? LCA_DEBUG : LCA_INFO);

  int fd = lca_atmel_setup (arguments.args[0], 0x60);

  if (fd < 0)
  {
      exit (1);
  }

  if (arguments.print_state)
  {
      int state = lca_get_device_state(fd);

	  switch (state)
	    {
		  case STATE_FACTORY:
		    printf("FACTORY\n");
		    rc = 0;
		    break;
		  case STATE_INITIALIZED:
		    printf("INITIALIZED\n");
		    rc = 0;
		    break;
		  case STATE_PERSONALIZED:
	        printf("PERSONALIZED\n");
	        rc = 0;
		    break;
		  default:
            printf("UNKNOWN\n");
            break;
	    }
  }
  else if (arguments.print_serial)
  {
      serial = lca_get_serial_num (fd);

      if (serial.ptr)
        {

          printf ("%02X", serial.ptr[0]);

          for (i = 1; i < serial.len; i++)
          {
            printf (":%02X", serial.ptr[i]);
          }

          printf("\n");

          rc = 0;
        }
  }
  else if (arguments.write_keys == 1)
  {
	  struct lca_octet_buffer config;
	  struct lca_octet_buffer slot_data;
	  uint16_t slot_config;
	  uint16_t key_config;

	  assert (lca_config2bin(arguments.input_file, &config) == 0);
	  assert (lca_get_slot_config(arguments.slot, config, &slot_config));
	  assert (lca_get_key_config(arguments.slot, config, &key_config));

	  if (0 == lca_write_key(fd, arguments.slot, arguments.input_file, slot_config, key_config))
		  rc = 0;
  }
  else if (arguments.personalize)
  {
      rc = personalize (fd, arguments.input_file);

      lca_idle(fd);

      sleep (1);

      lca_wakeup(fd);

      printf("\n");

      struct lca_octet_buffer response = get_otp_zone (fd);
      if (NULL != response.ptr)
        {
          printf("Verify OTP:");

          for (i = 0; i < response.len; i++)
	        {
	          if (i % 4 == 0)
		        printf("\n%04u : ", i);

	          printf ("%02X ", response.ptr[i]);
	        }

	      lca_free_octet_buffer (response);

	      rc = 0;
        }
      else
        {
          printf("Unable to get OTP");
        }

      printf("\n");
  }
  else if (arguments.write_config)
  {
      struct lca_octet_buffer result;

      assert (0 == lca_config2bin(arguments.input_file, &result));

      lca_wakeup(fd);

      assert (0 == lca_burn_config_zone (fd, result));

      lca_idle(fd);

      /* We need to wait until we can read back correct data */
      sleep (1);

      lca_wakeup(fd);

      printf("\n");

      struct lca_octet_buffer response = get_config_zone (fd);
      if (NULL != response.ptr)
        {
    	  unsigned int i = 0;

          printf("Verify configuration:");

    	  for (i = 0; i < response.len; i++)
    	    {
    		  if (i % 4 == 0)
    			printf("\n%04u : ", i);

              if (result.ptr[i] == response.ptr[i])
            	printf ("== ");
              else
    		    printf ("%02X ", response.ptr[i]);
    	    }

          lca_free_octet_buffer (response);
        }
      else
        {
          printf("Unable to get configuration");
          goto OUT;
        }

      printf("\n");

      lca_idle(fd);
      lca_wakeup(fd);

      if (arguments.lock)
          assert (0 == lca_lock_config_zone (fd, result));

      rc = 0;
  }

OUT:

  lca_idle(fd);

  close (fd);

  exit (rc);
}
