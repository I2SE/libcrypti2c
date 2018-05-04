/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2015 Cryptotronix, LLC.
 *
 * This file is part of libcryptoauth.
 *
 * libcryptoauth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libcryptoauth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libcryptoauth.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "util.h"
#include "command_util.h"
#include "atsha204_command.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include "crc.h"
#include "../libcryptoauth.h"

enum LCA_KEY_TYPE
lca_get_key_type(uint16_t key_config)
{
	return (key_config >> 2) & 0x7;
}

static struct lca_octet_buffer
parse_config_zone (xmlDocPtr doc, xmlNodePtr cur) {

  xmlChar *key;
  char *key_cp;
  cur = cur->xmlChildrenNode;
  int x = 0;
  const char tok[] = " ";
  char * token, * end;
  unsigned long val;


  struct lca_octet_buffer result = {0,0};

  uint8_t *configzone = NULL;

  while (cur != NULL)
    {

      key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
      if (NULL != key)
        {
          key_cp = strdup((const char *)key);
          token = strtok(key_cp, tok);

          while (token!=NULL)
            {
              configzone = realloc (configzone, x + 1);
              assert (NULL != configzone);
              val = strtoul(token, &end, 16);

              if (val > 0xFF)
                goto OUT;

              if (*end != '\0')
                goto OUT;

              configzone[x] = val;
              x+=1;

              // get the next token
              token = strtok(NULL, tok);

            }

          xmlFree(key);
          free(key_cp);
        }

      cur = cur->next;
    }

  result.ptr = configzone;
  result.len = x;

  return result;

 OUT:
  free(configzone);
  xmlFree(key);
  free(key_cp);

  return result;
}

bool
lca_get_slot_config(uint8_t slot, struct lca_octet_buffer config, uint16_t *slot_config)
{
  if (slot > 15)
    return false;

  if (!config.ptr)
    return false;

  if (config.len != 128)
    return false;

  *slot_config  = config.ptr[slot * 2 + 20] | config.ptr[slot * 2 + 21] << 8;

  return true;
}

bool
lca_get_key_config(uint8_t slot, struct lca_octet_buffer config, uint16_t *key_config)
{
  if (slot > 15)
    return false;

  if (!config.ptr)
    return false;

  if (config.len != 128)
    return false;

  *key_config  = config.ptr[slot * 2 + 96] | config.ptr[slot * 2 + 97] << 8;

  return true;
}

int
lca_config2bin(const char *docname, struct lca_octet_buffer *out)
{

  xmlDocPtr doc;
  xmlNodePtr cur;
  struct lca_octet_buffer tmp;
  int rc = -1;

  assert (NULL != docname);
  assert (NULL != out);

  doc = xmlParseFile(docname);

  if (doc == NULL)
    {
      fprintf(stderr,"Document not parsed successfully. \n");
      rc = -2;
      goto OUT;
    }

  cur = xmlDocGetRootElement(doc);

  if (cur == NULL)
    {
      fprintf(stderr,"empty document\n");
      rc = -3;
      goto FREE;
    }

  if (xmlStrcmp(cur->name, (const xmlChar *) "ECC108Content.01") &&
	  xmlStrcmp(cur->name, (const xmlChar *) "ECC508Content.01"))
    {
      fprintf(stderr,"document of unknown type, root node = <%s>\n", cur->name);
      rc = -4;
      goto FREE;
    }

  cur = cur->xmlChildrenNode;

  while (cur != NULL)
    {
      if ((!xmlStrcmp(cur->name, (const xmlChar *)"ConfigZone")))
        {
          tmp = parse_config_zone (doc, cur);
          if (NULL != tmp.ptr)
            {
              out->ptr = tmp.ptr;
              out->len = tmp.len;
              rc = 0;
            }

        }

      cur = cur->next;
    }

 FREE:
  xmlFreeDoc(doc);
 OUT:
  return rc;
}

static struct lca_octet_buffer
parse_otp_zone (xmlNodePtr cur) {

  xmlChar *key;
  char *key_cp;
  int x = 0;
  const char tok[] = " ";
  char * token, * end;
  unsigned long val;

  struct lca_octet_buffer result = {0,0};

  uint8_t *otpzone = NULL;

  key = xmlNodeGetContent(cur);
  if (NULL != key)
    {
      key_cp = strdup((const char *)key);
      token = strtok(key_cp, tok);

      while (token!=NULL)
        {
          otpzone = realloc (otpzone, x + 1);
          assert (NULL != otpzone);
          val = strtoul(token, &end, 16);

          if (val > 0xFF)
            goto OUT;

          if (*end != '\0')
            goto OUT;

          otpzone[x] = val;
          x+=1;

          // get the next token
          token = strtok(NULL, tok);

        }

      xmlFree(key);
      free(key_cp);
    }

  result.ptr = otpzone;
  result.len = x;

  return result;

 OUT:
  free(otpzone);
  xmlFree(key);
  free(key_cp);

  return result;
}

int
lca_otp2bin(const char *docname, struct lca_octet_buffer *out)
{

  xmlDocPtr doc;
  xmlNodePtr cur;
  struct lca_octet_buffer tmp;
  int rc = -1;

  assert (NULL != docname);
  assert (NULL != out);

  doc = xmlParseFile(docname);

  if (doc == NULL)
    {
      fprintf(stderr,"Document not parsed successfully. \n");
      rc = -2;
      goto OUT;
    }

  cur = xmlDocGetRootElement(doc);

  if (cur == NULL)
    {
      fprintf(stderr,"empty document\n");
      rc = -3;
      goto FREE;
    }

  if (xmlStrcmp(cur->name, (const xmlChar *) "ECC108Content.01") &&
	  xmlStrcmp(cur->name, (const xmlChar *) "ECC508Content.01"))
    {
      fprintf(stderr,"document of unknown type, root node = <%s>\n", cur->name);
      rc = -4;
      goto FREE;
    }

  cur = cur->xmlChildrenNode;

  while (cur != NULL)
    {
      if ((!xmlStrcmp(cur->name, (const xmlChar *)"OtpZone")))
        {
          tmp = parse_otp_zone (cur);
          if (NULL != tmp.ptr)
            {
              out->ptr = tmp.ptr;
              out->len = tmp.len;
              rc = 0;
            }

        }

      cur = cur->next;
    }

 FREE:
  xmlFreeDoc(doc);
 OUT:
  return rc;
}

static struct lca_octet_buffer
parse_data_zone (xmlDocPtr doc, xmlNodePtr cur, uint8_t slot) {

  xmlChar *key;
  char *key_cp;
  cur = cur->xmlChildrenNode;
  int s = 0, x = 0;
  const char tok[] = " ";
  char * token, * end;
  unsigned long val;

  struct lca_octet_buffer result = {0,0};

  uint8_t *slot_buf = NULL;

  while (cur != NULL)
    {
	  if ((xmlStrcmp(cur->name, (const xmlChar *)"Slot")))
	    {
		  cur = cur->next;
		  continue;
	    }

      if (s < slot)
		{
          s++;
          cur = cur->next;
		  continue;
		}

      key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
      if (NULL != key)
        {
	      key_cp = strdup((const char *)key);
	      token = strtok(key_cp, tok);


	      while (token!=NULL)
	        {
              slot_buf = realloc (slot_buf, x + 1);
		      assert (NULL != slot_buf);
		      val = strtoul(token, &end, 16);

		      if (val > 0xFF)
		        goto OUT;

		      if (*end != '\0')
		        goto OUT;

              slot_buf[x] = val;
		      x+=1;

		      // get the next token
		      token = strtok(NULL, tok);

	        }

	        xmlFree(key);
	        free(key_cp);
        }

      break;
    }

  result.ptr = slot_buf;
  result.len = x;

  return result;

 OUT:
  free(slot_buf);
  xmlFree(key);
  free(key_cp);

  return result;
}

int
lca_slot2bin(const char *docname, uint8_t slot, struct lca_octet_buffer *out)
{

  xmlDocPtr doc;
  xmlNodePtr cur;
  struct lca_octet_buffer tmp;
  int rc = -1;

  assert (NULL != docname);
  assert (NULL != out);

  doc = xmlParseFile(docname);

  if (doc == NULL)
    {
      fprintf(stderr,"Document not parsed successfully. \n");
      rc = -2;
      goto OUT;
    }

  cur = xmlDocGetRootElement(doc);

  if (cur == NULL)
    {
      fprintf(stderr,"empty document\n");
      rc = -3;
      goto FREE;
    }

  if (xmlStrcmp(cur->name, (const xmlChar *) "ECC108Content.01") &&
	  xmlStrcmp(cur->name, (const xmlChar *) "ECC508Content.01"))
    {
      fprintf(stderr,"document of unknown type, root node = <%s>\n", cur->name);
      rc = -4;
      goto FREE;
    }

  cur = cur->xmlChildrenNode;

  while (cur != NULL)
    {
      if ((!xmlStrcmp(cur->name, (const xmlChar *)"DataZone")))
        {
          tmp = parse_data_zone (doc, cur, slot);
          if (NULL != tmp.ptr)
            {
              out->ptr = tmp.ptr;
              out->len = tmp.len;
              rc = 0;
            }

        }

      cur = cur->next;
    }

 FREE:
  xmlFreeDoc(doc);
 OUT:
  return rc;
}

int
lca_write_key(int fd, const uint8_t key_slot, const char *config_file, uint16_t slot_config, uint16_t key_config)
{
  struct lca_octet_buffer data;
  struct lca_octet_buffer key;
  struct lca_octet_buffer write_key;
  uint8_t write_key_slot = (slot_config >> 8) & 0xF;
  int rc = -3;

  if (lca_slot2bin(config_file, key_slot, &data))
	  return -1;

  assert (data.ptr);
  assert (data.len);

  if (lca_slot2bin(config_file, write_key_slot, &write_key))
    {
	  lca_free_octet_buffer(data);
	  return -1;
    }

  if ((data.len == 36) &&
      (slot_config & (1 << 14)) &&
      (key_config & (1 << 0)) &&
	  (lca_get_key_type(key_config) != LCA_NO_ECC_TYPE))
    {
	  assert((0 == data.ptr[0]) && (0 == data.ptr[1]) && (0 == data.ptr[2]) && (0 == data.ptr[3]));

	  printf("Writing ECC private key to slot %u\n", key_slot);

	  /* ECC private key */
	  key.ptr = &data.ptr[4];
	  key.len = data.len - 4;
	  write_key.len -= 4;
	  rc = lca_priv_write_cmd(fd, true, key_slot, key, write_key_slot, write_key) ? 0 : -2;
    }
  else
    {
	  struct lca_octet_buffer block = lca_make_buffer (32);
      uint16_t addr;
      bool result;
      size_t i, len;

      if ((data.len == 72) &&
          (lca_get_key_type(key_config) != LCA_NO_ECC_TYPE))
        {
    	  /* ECC public key */
    	  assert((0 == data.ptr[0]) && (0 == data.ptr[1]) && (0 == data.ptr[2]) && (0 == data.ptr[3]));
    	  assert((0 == data.ptr[36]) && (0 == data.ptr[37]) && (0 == data.ptr[38]) && (0 == data.ptr[39]));

    	  printf("Writing ECC public key to slot %u\n", key_slot);
        }
      else
        {
    	  printf("Writing data[%u] of type %d to slot %u\n", data.len, lca_get_key_type(key_config), key_slot);
        }

      rc = 0;

      for (i = 0; i < data.len; )
        {
    	  memset(&block.ptr[0], 0, block.len);
    	  len = (data.len - i) > block.len ? block.len : (data.len - i);
          memcpy(&block.ptr[0], &data.ptr[i], len);
          addr = data_slot_to_addr(key_slot, i);
    	  if (!lca_write32_cmd (fd, DATA_ZONE, addr, block, NULL))
            rc = -2;

    	  i += len;
        }

      lca_free_octet_buffer(block);
    }

  lca_free_octet_buffer(write_key);
  lca_free_octet_buffer(data);

  return rc;
}

int
lca_verify_key(int fd, const uint8_t key_slot, const char *config_file, uint16_t slot_config, uint16_t key_config)
{
  struct lca_octet_buffer otp8 = lca_make_buffer (8);
  struct lca_octet_buffer otp3 = lca_make_buffer (3);
  struct lca_octet_buffer sn4 = lca_make_buffer (4);
  struct lca_octet_buffer sn23 = lca_make_buffer (2);
  struct lca_octet_buffer rand = lca_make_random_buffer (32);
  struct lca_octet_buffer digest_host;
  struct lca_octet_buffer digest_device;
  struct lca_octet_buffer data;
  struct lca_octet_buffer key;
  struct lca_octet_buffer rsp;
  int rc = -3;

  if (lca_slot2bin(config_file, key_slot, &data))
    {
	  rc = -1;
	  goto OUT;
    }

  assert (data.ptr);
  assert (data.len >= 32);

  key.ptr = &data.ptr[0];
  key.len = 32;

  digest_host = perform_hash(rand, key, 0x05, key_slot, otp8, otp3, sn4, sn23);

  rsp = lca_gen_nonce (fd, rand);

  digest_device = lca_gen_mac(fd, 0x05, key_slot, NULL);

  if (digest_device.ptr)
    {
	  if (memcmp(digest_host.ptr, digest_device.ptr, digest_host.len))
	    {
		  rc = -2;
	    }
	  else
	    {
		  rc = 0;
	    }

	  lca_free_octet_buffer(digest_device);
    }
  else
    {
	  rc = -1;
    }

  lca_free_octet_buffer(rsp);
  lca_free_octet_buffer(digest_host);
  lca_free_octet_buffer(data);

OUT:
  lca_free_octet_buffer(otp8);
  lca_free_octet_buffer(otp3);
  lca_free_octet_buffer(sn4);
  lca_free_octet_buffer(sn23);
  lca_free_octet_buffer(rand);

  return rc;
}

int
lca_burn_config_zone (int fd, struct lca_octet_buffer cz)
{
  bool config_locked = false;

  if (lca_is_config_locked (fd, &config_locked))
    {
      if (config_locked)
        return 0;
    }

  assert (0 == cz.len % 4);
  assert (NULL != cz.ptr);

  unsigned int x = 0;
  unsigned int retry;

  for (x = 16; x < cz.len; x+=4)
    {
      int addr = x >> 2;
      uint32_t *data = (uint32_t *)&cz.ptr[x];

      lca_idle(fd);
      lca_wakeup(fd);

      if (x == 84)
        {
    	  printf ("Write %02X %02X %02X %02X to %u skip\n", cz.ptr[x+0], cz.ptr[x+1], cz.ptr[x+2], cz.ptr[x+3], x);
    	  continue;
        }

      for (retry = 0; retry < 3; retry++)
        {
          if (write4 (fd, CONFIG_ZONE, addr, *data))
            {
              printf ("Write %02X %02X %02X %02X to %u success\n", cz.ptr[x+0], cz.ptr[x+1], cz.ptr[x+2], cz.ptr[x+3], x);
              break;
            }

          printf ("Write %02X %02X %02X %02X to %u Failure\n", cz.ptr[x+0], cz.ptr[x+1], cz.ptr[x+2], cz.ptr[x+3], x);
        }

    }

  return 0;

}

int
lca_lock_config_zone (int fd, const struct lca_octet_buffer template)
{

  struct lca_octet_buffer read_cz = get_config_zone (fd);

  assert (read_cz.ptr);
  assert (template.ptr);
  assert (read_cz.len == 128);
  assert (template.len == 128);

  /* The first 16 bytes are unique per device so backfill the template */
  memcpy (read_cz.ptr, template.ptr, 16);

  /* can't write to bytes 84,85,86,87 */
  memcpy (read_cz.ptr+84, template.ptr+84, 4);

  uint16_t crc = lca_calculate_crc16 (read_cz.ptr, read_cz.len);

  lca_free_octet_buffer (read_cz);

  if (lock (fd, CONFIG_ZONE, crc))
    return 0;
  else
    return -1;

}
