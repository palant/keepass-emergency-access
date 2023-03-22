let compositeKey;

kdbxweb.CryptoEngine.setArgon2Impl(async function(pass, salt, mem, time, hashLen, parallelism, type, version)
{
  pass = new Uint8Array(pass);
  salt = new Uint8Array(salt);
  return (await argon2.hash({
    pass,
    salt,
    mem,
    time,
    hashLen,
    parallelism,
    type,
    version
  })).hash;
});

function fromBase32(str)
{
  str = str.toUpperCase();
  if (str.length % 8)
    throw new Error("Unexpected: length of data decoded from base32 has to be a multiple of eight");

  let mapping = new Map();
  for (let i = 0; i < base32Alphabet.length; i++)
    mapping.set(base32Alphabet[i], i);

  let pos = 0;
  let current = 0;
  let currentBits = 0;
  let result = new Uint8Array(str.length / 8 * 5);
  for (let i = 0; i < str.length; i++)
  {
    current = (current << 5) | mapping.get(str[i]);
    currentBits += 5;
    if (currentBits >= 8)
    {
      let remainder = currentBits - 8;
      result[pos++] = current >> remainder;
      current &= ~(31 << remainder);
      currentBits = remainder;
    }
  }
  return result;
}

function processKey(i)
{
  let input = document.getElementById("key" + i);
  let value = input.value.replace(new RegExp(`[^${base32Alphabet}]`, "g"), "");
  if (value.length != 56)
  {
    input.setCustomValidity("Four full lines required.");
    return null;
  }

  let data = fromBase32(value);
  if (data[0] != 1)
  {
    input.setCustomValidity("Unrecognized key format.");
    return null;
  }

  if (crc16(data.slice(1)) != 0)
  {
    input.setCustomValidity("Checksum mismatch, probably a typo.");
    return null;
  }

  return data.slice(1, 33);
}

function processKeys()
{
  let result = new Uint8Array(32);
  for (let i = 1; document.getElementById("key" + i); i++)
  {
    let key = processKey(i);
    if (key)
    {
      if (result)
        for (let j = 0; j < result.length; j++)
          result[j] ^= key[j];
      key.fill(0);
    }
    else
      result = null;
  }
  return result ? result.buffer : null;
}

function displayPasswords(db)
{
  let group = db.getDefaultGroup();
  let fields = ["Title", "UserName", "Password", "URL", "Notes"];
  for (let entry of group.allEntries())
    for (let field of entry.fields.keys())
      if (!fields.includes(field))
        fields.push(field);

  let table = document.getElementById("result");
  let heading = table.tHead.rows[0];
  while (heading.cells.length > 2)
    heading.removeChild(heading.cells[heading.cells.length - 1]);

  for (let field of fields)
  {
    let cell = document.createElement("th");
    cell.textContent = field;
    heading.appendChild(cell);
  }

  while (table.tBodies.length > 0)
    table.removeChild(table.tBodies[table.tBodies.length - 1]);
  let tbody = document.createElement("tbody");
  for (let entry of group.allEntries())
  {
    let row = document.createElement("tr");

    {
      let cell = document.createElement("td");
      cell.textContent = entry.parentGroup.name;
      row.appendChild(cell);
    }

    {
      let cell = document.createElement("td");
      cell.textContent = entry.tags.join("\n");
      row.appendChild(cell);
    }

    for (let field of fields)
    {
      let cell = document.createElement("td");
      let value = entry.fields.get(field) || "";
      if (value.getText)
        value = value.getText();
      cell.textContent = value;
      row.appendChild(cell);
    }
    tbody.appendChild(row);
  }
  table.appendChild(tbody);

  table.hidden = false;
}

async function getPasswords(event)
{
  event.preventDefault();

  let submitButton = document.getElementById("submitButton");
  submitButton.disabled = true;

  try
  {
    let data;
    try
    {
      let response = await fetch(db_file, {cache: "no-cache"});
      data = await response.arrayBuffer();
    }
    catch (error)
    {
      console.error(error);
      alert("Failed to download passwords database " + db_file);
      return;
    }

    compositeKey = processKeys();
    if (!compositeKey)
    {
      alert("Some keys have been entered correctly.");
      return;
    }

    let db;
    try
    {
      let credentials = new kdbxweb.Credentials();
      credentials.getHash = () => Promise.resolve(compositeKey);
      db = await kdbxweb.Kdbx.load(data, credentials);
    }
    catch (error)
    {
      console.error(error);
      alert("Failed opening passwords database, maybe wrong keys?");
      return;
    }

    displayPasswords(db);
  }
  finally
  {
    submitButton.disabled = false;
  }
}

function processInput(event)
{
  if (event.target.localName != "textarea")
    return;

  function insert(str, substr, pos)
  {
    return str.slice(0, pos) + substr + str.slice(pos);
  }

  event.target.setCustomValidity("");

  let selectionDirection = event.target.selectionDirection;
  let value = event.target.value;
  value = insert(value, "\0", event.target.selectionEnd);
  value = insert(value, "\0", event.target.selectionStart);
  value = value.toUpperCase();

  value = value.replace(new RegExp(`[^${base32Alphabet}\0]`, "gi"), "");
  value = value.replace(/(?:\w\0*){13}\w/g, "$&\n");
  value = value.replace(/(?:\w\0*){6}\w(?=\0*\w)/g, "$&-");

  let selection = [value.indexOf("\0"), value.lastIndexOf("\0") - 1];
  event.target.value = value.replace(/\0/g, "");
  event.target.setSelectionRange(selection[0], selection[1], selectionDirection);
}

document.addEventListener("DOMContentLoaded", () =>
{
  document.addEventListener("input", processInput);
  document.getElementById("keys_form").addEventListener("submit", getPasswords);
}, {once: true});
