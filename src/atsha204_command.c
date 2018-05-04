/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2015 Cryptotronix, LLC.
 *
 * This file is part of EClet.
 *
 * EClet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * EClet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EClet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"
#include "atsha204_command.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../libcryptoauth.h"
#include "command_util.h"

struct Command_ATSHA204
lca_build_random_cmd (bool update_seed)
{
  uint8_t param2[2] = {0};
  uint8_t param1 = update_seed ? 0 : 1;

  struct Command_ATSHA204 c =
    build_command (COMMAND_RANDOM,
                   param1,
                   param2,
                   NULL, 0,
                   0, RANDOM_MAX_EXEC);

  return c;
}

struct lca_octet_buffer
lca_get_random (int fd, bool update_seed)
{
  uint8_t *random_buf = NULL;
  struct lca_octet_buffer buf = {0, 0};
  random_buf = lca_malloc_wipe (RANDOM_RSP_LENGTH);

  struct Command_ATSHA204 c = lca_build_random_cmd (update_seed);

  if (RSP_SUCCESS == lca_process_command (fd, &c, random_buf,
                                           RANDOM_RSP_LENGTH))
    {
      buf.ptr = random_buf;
      buf.len = RANDOM_RSP_LENGTH;
    }
  else
    {
      LCA_LOG (LCA_INFO, "Random command failed");
      free (random_buf);
    }

  return buf;



}

struct Command_ATSHA204
lca_build_read4_cmd (enum DATA_ZONE zone, uint16_t addr)
{

  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);
  param2[0] = addr & 0xFF;
  param2[1] = addr >> 8;

  struct Command_ATSHA204 c =
    build_command (COMMAND_READ,
                   param1,
                   param2,
                   NULL, 0,
                   0, READ_MAX_EXEC);

  return c;

}

bool
read4 (int fd, enum DATA_ZONE zone, uint16_t addr, uint32_t *buf)
{

  bool result = false;
  assert (NULL != buf);

  struct Command_ATSHA204 c = lca_build_read4_cmd (zone, addr);

  if (RSP_SUCCESS == lca_process_command (fd,
                                           &c,
                                           (uint8_t *)buf, sizeof (uint32_t)))
    {
	  LCA_LOG (LCA_DEBUG, "Read 4 success");
      result = true;
    }
  else
    {
	  LCA_LOG (LCA_INFO, "Read 4 failure");
    }

  return result;
}

struct Command_ATSHA204
lca_build_read32_cmd (enum DATA_ZONE zone, uint16_t addr)
{
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  uint8_t READ_32_MASK = 0b10000000;

  param1 |= READ_32_MASK;

  param2[0] = addr & 0xFF;
  param2[1] = addr >> 8;

  struct Command_ATSHA204 c =
    build_command (COMMAND_READ,
                   param1,
                   param2,
                   NULL, 0,
                   0, READ_MAX_EXEC);

  return c;

}

struct lca_octet_buffer
read32 (int fd, enum DATA_ZONE zone, uint16_t addr)
{

  struct Command_ATSHA204 c = lca_build_read32_cmd (zone, addr);

  const unsigned int LENGTH_OF_RESPONSE = 32;
  struct lca_octet_buffer buf = lca_make_buffer (LENGTH_OF_RESPONSE);

  if (RSP_SUCCESS != lca_process_command (fd, &c, buf.ptr, LENGTH_OF_RESPONSE))
    {
	  LCA_LOG (LCA_INFO, "Read 32 failure");
      lca_free_wipe (buf.ptr, LENGTH_OF_RESPONSE);
      buf.ptr = NULL;
      buf.len = 0;
    }

  return buf;
}


struct Command_ATSHA204
lca_build_write4_cmd (enum DATA_ZONE zone, uint16_t addr, uint32_t buf)
{

  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  param2[0] = addr & 0xFF;
  param2[1] = addr >> 8;

  struct Command_ATSHA204 c =
    build_command (COMMAND_WRITE,
                   param1,
                   param2,
                   (uint8_t *)&buf, sizeof (buf),
                   0, WRITE_MAX_EXEC);

  return c;

}

bool
write4 (int fd, enum DATA_ZONE zone, uint16_t addr, uint32_t buf)
{

  bool status = false;
  uint8_t recv = 0;

  struct Command_ATSHA204 c = lca_build_write4_cmd (zone, addr, buf);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &recv, sizeof (recv)))
  {
	LCA_LOG (LCA_DEBUG, "Write 4 success");
    if (0 == (int) recv)
      status = true;
  }
  else
  {
	LCA_LOG (LCA_INFO, "Write 4 failure");
  }

  return status;

}

struct Command_ATSHA204
lca_build_write32_cmd (const enum DATA_ZONE zone,
                        const uint16_t addr,
                        const struct lca_octet_buffer buf,
                        const struct lca_octet_buffer *mac)
{

  assert (NULL != buf.ptr);
  assert (32 == buf.len);
  if (NULL != mac)
    assert (NULL != mac->ptr);

  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  struct lca_octet_buffer data = {0,0};

  if (NULL != mac)
    data = lca_make_buffer (buf.len + mac->len);
  else
    data = lca_make_buffer (buf.len);

  memcpy (data.ptr, buf.ptr, buf.len);
  if (NULL != mac && mac->len > 0)
    memcpy (data.ptr + buf.len, mac->ptr, mac->len);

  /* If writing 32 bytes, this bit must be set in param1 */
  uint8_t WRITE_32_MASK = 0b10000000;

  param1 |= WRITE_32_MASK;

  param2[0] = addr & 0xFF;
  param2[1] = addr >> 8;

  struct Command_ATSHA204 c =
    build_command (COMMAND_WRITE,
                   param1,
                   param2,
                   data.ptr, data.len,
                   0, WRITE_MAX_EXEC);

  return c;

}

bool
lca_write32_cmd (const int fd,
                  const enum DATA_ZONE zone,
                  const uint16_t addr,
                  const struct lca_octet_buffer buf,
                  const struct lca_octet_buffer *mac)
{

  bool status = false;
  uint8_t recv = 0;

  struct Command_ATSHA204 c =
    lca_build_write32_cmd (zone,
                            addr,
                            buf,
                            mac);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &recv, sizeof (recv)))
  {
    LCA_LOG (LCA_DEBUG, "Write 32 success");
    if (0 == (int) recv)
      status = true;
  }
  else
  {
    LCA_LOG (LCA_INFO, "Write 32 failure");
  }

  if (NULL != c.data)
    free (c.data);

  return status;
}

bool
lca_is_locked (int fd, enum DATA_ZONE zone, bool *locked_out)
{
  const uint16_t config_addr = 0x0010;
  const uint8_t UNLOCKED = 0x55;
  const unsigned int CONFIG_ZONE_OFFSET = 23;
  const unsigned int DATA_ZONE_OFFSET = 22;
  unsigned int offset = 0;
  uint8_t * ptr = NULL;

  switch (zone)
    {
    case CONFIG_ZONE:
      offset = CONFIG_ZONE_OFFSET;
      break;
    case DATA_ZONE:
    case OTP_ZONE:
      offset = DATA_ZONE_OFFSET;
      break;
    default:
      assert (false);

    }

  struct lca_octet_buffer config_data = read32 (fd, CONFIG_ZONE, config_addr);

  if (config_data.ptr != NULL)
    {
      ptr = config_data.ptr + offset;
      if (UNLOCKED == *ptr)
        *locked_out = false;
      else
        *locked_out = true;

      lca_free_octet_buffer (config_data);
      return true;
    }

  return false;
}

bool
lca_is_config_locked (int fd, bool *locked_out)
{
  return lca_is_locked (fd, CONFIG_ZONE, locked_out);
}

bool
lca_is_data_locked (int fd, bool *locked_out)
{
  return lca_is_locked (fd, DATA_ZONE, locked_out);
}


struct lca_octet_buffer
get_config_zone (int fd)
{
  const unsigned int SIZE_OF_CONFIG_ZONE = 128;
  const unsigned int NUM_OF_WORDS = SIZE_OF_CONFIG_ZONE / 4;

  struct lca_octet_buffer buf = lca_make_buffer (SIZE_OF_CONFIG_ZONE);
  uint8_t *write_loc = buf.ptr;

  unsigned int addr = 0;
  unsigned int word = 0;

  while (word < NUM_OF_WORDS)
    {
      addr = word * 4;
      if (false == read4 (fd, CONFIG_ZONE, word, (uint32_t*)(write_loc+addr)))
        {
    	  free (buf.ptr);
    	  buf.ptr = NULL;
    	  return buf;
        }
      word++;
    }

  return buf;
}

struct lca_octet_buffer
get_otp_zone (int fd)
{
    const unsigned int SIZE_OF_OTP_ZONE = 64;
    const unsigned int SIZE_OF_READ = 32;
    const unsigned int SIZE_OF_WORD = 4;
    const unsigned int SECOND_WORD = (SIZE_OF_READ / SIZE_OF_WORD);

    struct lca_octet_buffer buf = lca_make_buffer (SIZE_OF_OTP_ZONE);
    struct lca_octet_buffer half;

    int x = 0;

    for (x=0; x < 2; x++ )
      {
        int addr = x * SECOND_WORD;
        int offset = x * SIZE_OF_READ;

        half = read32 (fd, OTP_ZONE, addr);
        if (NULL != half.ptr)
          {
            memcpy (buf.ptr + offset, half.ptr, SIZE_OF_READ);
            lca_free_octet_buffer (half);
          }
        else
          {
            lca_free_octet_buffer (buf);
            buf.ptr = NULL;
            return buf;
          }

      }

    return buf;
}

bool
lock (int fd, enum DATA_ZONE zone, uint16_t crc)
{

  uint8_t param1 = 0;
  uint8_t param2[2];
  uint8_t response;
  bool result = false;

  if (lca_is_locked (fd, zone, &result))
    {
      if (result)
        return true;
    }

  memcpy (param2, &crc, sizeof (param2));

  const uint8_t CONFIG_MASK = 0;
  const uint8_t DATA_MASK = 1;

  switch (zone)
    {
    case CONFIG_ZONE:
      param1 |= CONFIG_MASK;
      break;
    case DATA_ZONE:
    case OTP_ZONE:
      param1 |= DATA_MASK;
      break;
    default:
      assert (false);
    }

  /* ignore the crc */
  param1 |= 0x80;
  crc = 0;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_LOCK);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, LOCK_MAX_EXEC);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &response, sizeof (response)))
    {
      if (0 == response)
        {
          result = true;
          LCA_LOG (LCA_DEBUG, "Lock Successful");
        }
      else
        {
          LCA_LOG (LCA_INFO, "Lock Failed");
        }
    }


  return result;

}

static bool
is_otp_read_only_mode (int fd)
{
  const uint16_t ADDR = 0x0004;
  uint32_t word = 0;
  assert (read4 (fd, CONFIG_ZONE, ADDR, &word));

  uint8_t * byte = (uint8_t *)&word;

  const unsigned int OFFSET_TO_OTP_MODE = 2;
  const unsigned int OTP_READ_ONLY_MODE = 0xAA;

  return OTP_READ_ONLY_MODE == byte[OFFSET_TO_OTP_MODE] ? true : false;


}


bool
set_otp_zone (int fd, struct lca_octet_buffer *otp_zone)
{

  assert (NULL != otp_zone);

  const unsigned int SIZE_OF_WRITE = 32;
  /* The device must be using an OTP read only mode */

  if (!is_otp_read_only_mode (fd))
    assert (false);

  /* The writes must be done in 32 bytes blocks */

  uint8_t nulls[SIZE_OF_WRITE];
  uint8_t part1[SIZE_OF_WRITE];
  uint8_t part2[SIZE_OF_WRITE];
  struct lca_octet_buffer buf = {0,0};
  lca_wipe (nulls, SIZE_OF_WRITE);
  lca_wipe (part1, SIZE_OF_WRITE);
  lca_wipe (part2, SIZE_OF_WRITE);

  /* Simple check to make sure PACKAGE_VERSION isn't too long */
  assert (strlen (PACKAGE_VERSION) < 10);

  /* Setup the fixed OTP data zone */
  sprintf ((char *)part1, "CRYPTOTRONIX ECLET REV: A");
  sprintf ((char *)part2, "SOFTWARE VERSION: %s", PACKAGE_VERSION);

  bool success = true;

  buf.ptr = nulls;
  buf.len = sizeof (nulls);

  /* Fill the OTP zone with blanks from their default FFFF */
  success = lca_write32_cmd (fd, OTP_ZONE, 0, buf, NULL);

  if (success)
    success = lca_write32_cmd (fd, OTP_ZONE, SIZE_OF_WRITE / sizeof (uint32_t),
                                buf, NULL);

  /* Fill in the data */
  buf.ptr = part1;
  LCA_LOG (LCA_DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = lca_write32_cmd (fd, OTP_ZONE, 0, buf, NULL);
  buf.ptr = part2;
  LCA_LOG (LCA_DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = lca_write32_cmd (fd, OTP_ZONE, SIZE_OF_WRITE / sizeof (uint32_t),
                                buf, NULL);

  /* Lastly, copy the OTP zone into one contiguous buffer.
     Ironically, the OTP can't be read while unlocked. */
  if (success)
    {
      otp_zone->len = SIZE_OF_WRITE * 2;
      otp_zone->ptr = lca_malloc_wipe (otp_zone->len);
      memcpy (otp_zone->ptr, part1, SIZE_OF_WRITE);
      memcpy (otp_zone->ptr + SIZE_OF_WRITE, part2, SIZE_OF_WRITE);
    }
  return success;
}


struct lca_octet_buffer
lca_get_serial_num (int fd)
{
  struct lca_octet_buffer serial;
  const unsigned int len = sizeof (uint32_t) * 2 + 1;
  serial.ptr = lca_malloc_wipe (len);
  serial.len = len;

  uint32_t word = 0;

  const uint16_t SERIAL_PART1_ADDR = 0x0000;
  const uint16_t SERIAL_PART2_ADDR = 0x0002;
  const uint16_t SERIAL_PART3_ADDR = 0x0003;

  if (!read4 (fd, CONFIG_ZONE, SERIAL_PART1_ADDR, &word))
	  goto FAIL;

  memcpy (serial.ptr, &word, sizeof (word));

  if (!read4 (fd, CONFIG_ZONE, SERIAL_PART2_ADDR, &word))
	  goto FAIL;

  memcpy (serial.ptr + sizeof (word), &word, sizeof (word));

  if (!read4 (fd, CONFIG_ZONE, SERIAL_PART3_ADDR, &word))
	  goto FAIL;

  uint8_t * ptr = (uint8_t *)&word;

  memcpy (serial.ptr + len - 1, ptr, 1);

  return serial;

FAIL:

  lca_free_octet_buffer (serial);
  serial.len = 0;
  serial.ptr = NULL;

  return serial;
}


enum DEVICE_STATE
lca_get_device_state (int fd)
{
  bool config_locked;
  bool data_locked;
  enum DEVICE_STATE state = STATE_FACTORY;

  if (!lca_is_config_locked (fd, &config_locked))
    state = STATE_UNKNOWN;
  else if (!lca_is_data_locked (fd, &data_locked))
    state = STATE_UNKNOWN;
  else if (!config_locked && !data_locked)
    state = STATE_FACTORY;
  else if (config_locked && !data_locked)
    state = STATE_INITIALIZED;
  else if (config_locked && data_locked)
    state = STATE_PERSONALIZED;
  else
    state = STATE_UNKNOWN;

  return state;

}


struct lca_octet_buffer
lca_gen_nonce (int fd, struct lca_octet_buffer data)
{
  const unsigned int EXTERNAL_INPUT_LEN = 32;
  const unsigned int NEW_NONCE_LEN = 20;

  assert (NULL != data.ptr && (EXTERNAL_INPUT_LEN == data.len ||
                               NEW_NONCE_LEN == data.len));

  uint8_t param2[2] = {0};
  uint8_t param1 = 0;

  unsigned int rsp_len = 0;

  if (EXTERNAL_INPUT_LEN == data.len)
    {
      const unsigned int PASS_THROUGH_MODE = 3;
      const unsigned int RSP_LENGTH = 1;
      param1 = PASS_THROUGH_MODE;
      rsp_len = RSP_LENGTH;
    }
  else
    {
      const unsigned int COMBINE_AND_UPDATE_SEED = 0;
      const unsigned int RSP_LENGTH = 32;
      param1 = COMBINE_AND_UPDATE_SEED;
      rsp_len = RSP_LENGTH;
    }

  struct lca_octet_buffer buf = lca_make_buffer (rsp_len);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_NONCE);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, data.ptr, data.len);
  set_execution_time (&c, 0, NONCE_MAX_EXEC);

  if (RSP_SUCCESS != lca_process_command (fd, &c, buf.ptr, buf.len))
    {
      LCA_LOG (LCA_INFO, "Nonce command failed");
      lca_free_octet_buffer (buf);
      buf.ptr = NULL;
    }

  return buf;



}

struct lca_octet_buffer
get_nonce (int fd)
{
  struct lca_octet_buffer otp;
  struct lca_octet_buffer nonce = {0, 0};
  const unsigned int MIX_DATA_LEN = 20;

  otp = get_otp_zone (fd);
  unsigned int otp_len = otp.len;

  if (otp.len > MIX_DATA_LEN && otp.ptr != NULL)
    {
      otp.len = MIX_DATA_LEN;
      nonce = lca_gen_nonce (fd, otp);
      otp.len = otp_len;

    }

  lca_free_octet_buffer (otp);

  return nonce;
}


bool
load_nonce (int fd, struct lca_octet_buffer data)
{
  assert (data.ptr != NULL && data.len == 32);

  struct lca_octet_buffer rsp = lca_gen_nonce (fd, data);

  if (NULL == rsp.ptr || *rsp.ptr != 0)
    return false;
  else
    return true;

}

bool
lca_gen_digest (int fd, const enum DATA_ZONE zone, uint16_t key_id, struct lca_octet_buffer *other_data)
{
  uint8_t result = 0xFF;

  uint8_t param2[2] = {0};

  param2[0] = key_id & 0xFF;
  param2[1] = key_id >> 8;

  switch (zone)
    {
      case CONFIG_ZONE:
      case OTP_ZONE:
      case DATA_ZONE:
        // data + opcode + param1 + param2 + SN[8] + SN[0:1] + zeros + tempkey
        assert(NULL == other_data);
        break;
      case COUNTER_ZONE:
        // zeros + opcode + param1 + param2 + SN[8] + SN[0:1] + zero + counter[key_id] + zeros + tempkey
        assert(NULL == other_data);
        break;
      case KEY_CONFIG_ZONE:
        // tempkey + opcode + mode + param2 + SN[8] + SN[0:1] + zero + slot_config[key_id] + key_config[key_id] + slot_locked:key_id + zeros
        assert(false);
        break;
      case SHARED_NONCE_ZONE:
        // other_data + opcode + mode + LSB of key_id + zero + SN[8] + SN[0:1] + zeros + tempkey
        assert(other_data && other_data->len == 32);
        break;
      default:
        assert(false);
        break;
    }

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_GEN_DIG);
  set_param1 (&c, zone);
  set_param2 (&c, param2);

  if (other_data)
    set_data (&c, other_data->ptr, other_data->len);

  set_execution_time (&c, 0, GEN_DIG_MAX_EXEC);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &result, sizeof(result)))
    {
      LCA_LOG (LCA_DEBUG, "GenDig success");
      return result == 0;
    }
  else
    {
      LCA_LOG (LCA_INFO, "GenDig failure");
    }

  return false;
}

struct lca_octet_buffer
lca_gen_mac(const int fd,
            const uint8_t mode,
            const uint16_t key_id,
            const struct lca_octet_buffer *challenge)
{
  assert ((mode & 1) || (challenge && challenge->len == 32));

  uint8_t param2[2] = {0};

  param2[0] = key_id & 0xFF;
  param2[1] = key_id >> 8;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_MAC);
  set_param1 (&c, mode);
  set_param2 (&c, param2);

  if (mode & 1 == 0)
    set_data (&c, challenge->ptr, challenge->len);

  set_execution_time (&c, 0, MAC_MAX_EXEC);

  struct lca_octet_buffer buf = lca_make_buffer (32);

  if (RSP_SUCCESS != lca_process_command (fd, &c, buf.ptr, buf.len))
    {
	  LCA_LOG (LCA_INFO, "MAC failure");
	  lca_free_octet_buffer (buf);
	  buf.ptr = NULL;
    }

  return buf;
}
