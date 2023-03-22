#!/usr/bin/env node

"use strict";

import inquirer from "inquirer";
import yargs from "yargs/yargs";
import {hideBin} from "yargs/helpers";

import {readDatabase, getDatabaseKey, writeOutput, printKeys} from "../lib/index.js";

function parseArgs()
{
  return yargs(hideBin(process.argv))
    .option("num_keys", {
      alias: "n",
      description: "Number of keys to generate",
      type: "number",
      coerce: input =>
      {
        let result = parseInt(input, 10);
        if (isNaN(result) || result < 1)
          throw new Error("Invalid number of keys given, has to be 1 or more.");
        if (result == 1)
          console.warn("Warning: Generating only one key, this key alone will grant password access. Keep it somewhere safe!");
        return result;
      },
      default: 2
    })
    .option("password", {
      alias: "p",
      description: "Master password for the database. If omitted, will have to be entered."
    })
    .option("key_file", {
      alias: "k",
      description: "Additional key file"
    })
    .option("overwrite", {
      alias: "y",
      description: "Overwrite existing files without asking"
    })
    .positional("db_file", {
      description: "KeePass database file in KDBX4 format"
    })
    .positional("output_file", {
      description: "HTML file to be written"
    })
    .usage("$0 <db_file> <output_file>", "Generates an HTML file to access a database's passwords and generates a number of keys. All keys have to be entered correctly in order to access the database.")
    .version(false)
    .parse();
}

async function queryPassword()
{
  let {password} = await inquirer.prompt([{
    type: "password",
    name: "password",
    message: "Please enter the database password:"
  }]);
  return password;
}

async function run()
{
  let args = parseArgs();
  if (!args.password)
    args.password = queryPassword;

  let [credentials, database] = await readDatabase(args);
  let compositeKey = await getDatabaseKey(credentials, database);
  await writeOutput(args);
  printKeys(args, compositeKey);
  console.log("Access to your passwords can only be gained with all of these keys, so keep them separate!");
}

run();
