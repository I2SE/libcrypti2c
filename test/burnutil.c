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
  "Utility for burning the config and otp zones";

/* A description of the arguments we accept. */
static char args_doc[] = "BUS";

/* Number of required args */
#define NUM_ARGS 1

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"silent",   's', 0,      OPTION_ALIAS },
  {"lock",     'l', 0,      0,  "Locks zones"},
  {"personalize",     'p', 0,      0,  "Fully personalizes device"},
  {"file",     'f', "XMLFILE", 0,
   "XML Memory configuration file" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
    char *args[NUM_ARGS];                /* arg1 & arg2 */
    int silent, verbose, lock, personalize;
    char *display, *input_file;
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
    case 'q': case 's':
      arguments->silent = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      break;
    case 'l':
      arguments->lock = 1;
      break;
    case 'p':
        arguments->personalize = 1;
        break;
    case 'f':
      arguments->input_file = arg;
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
  int rc = -1;

  /* Default values. */
  arguments.silent = 0;
  arguments.verbose = 0;
  arguments.lock = 0;
  arguments.personalize = 0;
  arguments.input_file = NULL;


  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  if (NULL == arguments.input_file)
  {
      printf("Need xml file\n");
      exit (1);
  }

  lca_init_and_debug (INFO);

  int fd = lca_atmel_setup (arguments.args[0], 0x60);

  if (fd < 0)
  {
	  exit (1);
  }

  int state = lca_get_device_state(fd);
  lca_idle(fd);

  printf("Device state: ");

  switch (state) {
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

  printf("\n");

  if (arguments.personalize)
  {
      lca_wakeup(fd);

      rc = personalize (fd, arguments.input_file);

      lca_idle(fd);

      sleep (1);

      lca_wakeup(fd);

      printf("\n");
      printf("Verify OTP:");

      struct lca_octet_buffer response = get_otp_zone (fd);
      if (NULL != response.ptr)
        {
          unsigned int i = 0;

          for (i = 0; i < response.len; i++)
	        {
	          if (i % 4 == 0)
		        printf("\n%04u : ", i);

	          printf ("%02X ", response.ptr[i]);
	        }

	      lca_free_octet_buffer (response);
        }

      printf("\n");
  }
  else
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
      printf("Verify configuration:");

      struct lca_octet_buffer response = get_config_zone (fd);
      if (NULL != response.ptr)
        {
    	  unsigned int i = 0;

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

      printf("\n");

      lca_idle(fd);
      lca_wakeup(fd);

      if (arguments.lock)
          assert (0 == lca_lock_config_zone (fd, result));

      rc = 0;
  }

  close (fd);

  exit (rc);
}
