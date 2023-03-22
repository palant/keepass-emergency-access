#!/usr/bin/env node

"use strict";

import crypto from "node:crypto";
import fs from "node:fs/promises";
import module from "node:module";
import path from "node:path";
import url from "node:url";

import argon2 from "argon2";
import inquirer from "inquirer";
import kdbxweb from "kdbxweb";

export async function readDatabase(args)
{
  kdbxweb.CryptoEngine.setArgon2Impl(function(password, salt, memoryCost, timeCost, hashLength, parallelism, type, version)
  {
    salt = Buffer.from(salt);
    return argon2.hash(password, {
      raw: true,
      salt,
      memoryCost,
      timeCost,
      hashLength,
      parallelism,
      type,
      version
    });
  });

  let data = await fs.readFile(args.db_file);
  let key = args.key_file ? (await fs.readFile(args.key_file)).buffer : null;

  for (let firstAttempt = true; ; firstAttempt = false)
  {
    let actual_password = args.password;
    if (typeof actual_password == "function")
      actual_password = await actual_password(firstAttempt);

    let credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(actual_password), key);
    try
    {
      return [credentials, await kdbxweb.Kdbx.load(data.buffer, credentials)];
    }
    catch (error)
    {
      if (error instanceof kdbxweb.KdbxError && error.code == "InvalidKey" && typeof args.password == "function")
        continue;
      throw error;
    }
  }
}

export async function getDatabaseKey(credentials, database)
{
  if (database.header.versionMajor != 4)
    throw new Error(`Expected database version 4, got ${database.header.versionMajor}`);

  let kdfParams = database.header.kdfParameters;
  let kdfSalt = kdfParams.get("S");
  let compositeKey = await credentials.getHash(kdfSalt);
  if (compositeKey.byteLength != 32)
    throw new Error(`Expected key length 32, got ${compositeKey.byteLength}`);
  return compositeKey;
}

export async function writeOutput(args)
{
  let template_file = path.join(path.dirname(url.fileURLToPath(import.meta.url)), "..", "assets", "template.html");
  let template = await fs.readFile(template_file, {encoding: "utf-8"});

  let require = module.createRequire(import.meta.url);
  let template_script = await fs.readFile(require.resolve("../assets/template.js"), {encoding: "utf-8"});
  let kdbx_script = await fs.readFile(require.resolve("kdbxweb/dist/kdbxweb.min.js"), {encoding: "utf-8"});
  let argon2_script = await fs.readFile(require.resolve("argon2-browser/dist/argon2-bundled.min.js"), {encoding: "utf-8"});

  template = template.replace(/{{(\w+)}}/g, (match, keyword) =>
  {
    if (keyword == "script")
      return template_script;
    else if (keyword == "kdbxweb")
      return kdbx_script;
    else if (keyword == "argon2")
      return argon2_script;
    else if (keyword == "crc")
      return crc16.toString();
    else if (keyword == "base32")
      return JSON.stringify(base32Alphabet);
    else if (keyword == "kdbx_file")
      return JSON.stringify(path.basename(args.db_file));
    else
      return match;
  });

  template = template.replace(/{{key_entry_start}}(.*?){{key_entry_end}}/s, (match, contents) =>
  {
    let result = [];
    for (let i = 0; i < args.num_keys; i++)
      result.push(contents.replace(/{{key_index}}/g, i + 1));
    return result.join("\n");
  });

  if (!args.overwrite)
  {
    try
    {
      await fs.stat(args.output_file);
      let {overwrite} = await inquirer.prompt([{
        type: "confirm",
        name: "overwrite",
        default: false,
        message: "The output file already exists. Overwrite?"
      }]);
      if (!overwrite)
        throw new Error("Operation canceled.");
    }
    catch (error)
    {
      if (error.code != "ENOENT")
        throw error;
    }
  }

  await fs.writeFile(args.output_file, template);
}

function crc16(arr)
{
  // Precomputed table for CRC-16-CCITT (polynomial 0x1021)
  const table = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
  ];

  let crc = 0xFFFF;
  for (let i = 0; i < arr.length; i++)
    crc = ((crc << 8) ^ table[(crc >> 8) ^ arr[i]]) & 0xFFFF;
  return crc;
}

// Our Base32 variant follows RFC 4648 but uses a custom alphabet to remove
// ambiguous characters: 0, 1, O, I.
const base32Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function toBase32(buffer)
{
  let pos = 0;
  let current = 0;
  let currentBits = 0;
  let result = [];
  while (pos < buffer.length || currentBits >= 5)
  {
    if (currentBits < 5)
    {
      current = (current << 8) | buffer[pos++];
      currentBits += 8;
    }

    let remainder = currentBits - 5;
    result.push(base32Alphabet[current >> remainder]);
    current &= ~(31 << remainder);
    currentBits = remainder;
  }

  // Our input is always padded, so there should never be data left here
  if (currentBits)
    throw new Error("Unexpected: length of data encoded to base32 has to be a multiple of five");

  return result.join("");
}

function stringifyKey(key)
{
  if (key.length != 32)
    throw new Error(`Expected key length 32, got ${key.length}`);

  let data = new Uint8Array(35);
  data[0] = 1;  // version
  data.set(key, 1);

  let crc = crc16(key);
  data[33] = crc >> 8;
  data[34] = crc & 0xFF;

  let encoded = toBase32(data);
  return encoded.match(/.{14}/g).join("\n");
}

export function* generateKeys(args, compositeKey)
{
  compositeKey = new Uint8Array(compositeKey);

  for (let i = 0; i < args.num_keys - 1; i++)
  {
    let key = new Uint8Array(compositeKey.length);
    crypto.getRandomValues(key);

    for (let j = 0; j < compositeKey.length; j++)
      compositeKey[j] ^= key[j];

    yield [i + 1, stringifyKey(key)];
    key.fill(0);
  }

  yield [args.num_keys, stringifyKey(compositeKey)];
  compositeKey.fill(0);
}
