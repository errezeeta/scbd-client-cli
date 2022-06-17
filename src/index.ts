import { TaskCollection } from "./models/taskCollection";
import inquirer from "inquirer";
import { JsonTaskCollection } from "./models/jsonTaskCollection";
import { tasks } from "./exampleData";
import {generateKeys, RsaKeyPair, RsaPublicKey} from '@scbd/rsa';
import * as sha from 'object-sha';
import * as bic from 'bigint-conversion';
import * as bcu from 'bigint-crypto-utils';
import fetch from 'node-fetch';
import * as paillierBigint from 'paillier-bigint';
const bitLength = 1024;
var username: string = " ";
var password: string = " ";
var response;
var responseSer;
var keysCE: RsaPublicKey;
var cert: String;
var voted: boolean = false;
var access : boolean = false;
var hascert: boolean = false;

let collection: TaskCollection = new JsonTaskCollection("Fazt", tasks);
let showCompleted = true;

async function displayTaskList(): Promise<void> {
  if (access == true) {
    console.log(
      `Proyecto SCBD Grupo 4\n`+
      "Bienvenido "+username+"!"
    );
  }
  else {
    console.log(
      `Proyecto SCBD Grupo 4`
    );
  }
}

enum Commands {
  Login = "Iniciar sesion",
  KeySee = "Ver mi clave",
  CEKeySee = "Ver clave pública de la CE",
  GetCert = "Solicitar certificado",
  Vote = "Votar",
  Quit = "Quit",
}

enum Commands2 {
  Back = "Volver"
}

enum Votacion {
  Laporta = "Joan Laporta",
  Bartomeu = "Josep Maria Bartomeu",
  Back = "Volver"
}

async function login(): Promise<void> {
  console.clear();
  const answers = await inquirer.prompt({
    type: "input",
    name: "add",
    message: "Nombre de usuario:"
  });
  if (answers["add"] !== "") {
    username = answers["add"];
  }
  enterpass();
}

async function enterpass() {
  console.clear();
  const answers = await inquirer.prompt({
    type: "input",
    name: "add",
    message: "Contraseña:"
  });
  if (answers["add"] !== "") {
    password = answers["add"];
  }
  sendServer();
}

async function sendServer() {
  console.clear();
  response = await fetch("http://localhost:8080/rsa/login", {
      method: 'POST',
      body: JSON.stringify({
        username: username,
        password: password,
      }),
      headers: {'Content-Type': 'application/json',
    } 
    });
    const data = await response.json();
    response = await (JSON.parse(JSON.stringify(data)));
    if (await response.message === "login complete") {
      const secondRes = await fetch("http://localhost:8080/rsa/pubK_CE", {
        method: 'POST',
        body: JSON.stringify({
          username: username,
          password: password,
        }),
        headers: {'Content-Type': 'application/json',
      } 
      });
      const res = await secondRes.json();
      const parsedKeys = await (JSON.parse(JSON.stringify(res)));
      keysCE = new RsaPublicKey(bic.base64ToBigint(parsedKeys.e), bic.base64ToBigint(parsedKeys.n));
      console.log("MIS keys: "+ keysCE.toJsonString());
      access = true;
    }
    else {
      console.log("Error al iniciar sesión, porfavor, vuelve a intentarlo");
      const answers = await inquirer.prompt({
        type: "list",
        name: "command",
        message: " ",
        choices: Object.values(Commands2)
      });
      switch (answers["command"]) {
        case Commands2.Back:
          promptUser();
          break;
      }
    }
    promptUser();
}

async function promptComplete(): Promise<void> {
  console.clear();
  const answers = await inquirer.prompt({
    type: "checkbox",
    name: "complete",
    message: "Mark Task Complete",
    choices: collection.getTaskItems(showCompleted).map(item => ({
      name: item.task,
      value: item.id,
      checked: item.complete
    }))
  });
  let completedTasks = answers["complete"] as number[];
  collection
    .getTaskItems(true)
    .forEach(item =>
      collection.markComplete(
        item.id,
        completedTasks.find(id => id === item.id) != undefined
      )
    );
  promptUser();
}

async function keyGen() {
  const keyPair: RsaKeyPair = await generateKeys(bitLength);
  return keyPair;
}

async function keySee() {
  if (keys != undefined) {
    console.clear();
    console.log("Tu clave publica és: "+(await keys).publicKey.toJsonString());
    const answers = await inquirer.prompt({
      type: "list",
      name: "command",
      message: "Elige una opción",
      choices: Object.values(Commands2)
    });
    switch (answers["command"]) {
      case Commands2.Back:
        promptUser();
        break;
    }
  }
  else {
    console.clear();
    console.log("Aún no dispones de claves");
    const answers = await inquirer.prompt({
      type: "list",
      name: "command",
      message: "Elige una opción",
      choices: Object.values(Commands2)
    });
    switch (answers["command"]) {
      case Commands2.Back:
        promptUser();
        break;
    }
  }
}

async function getCert(keys: RsaKeyPair, keysCE: RsaPublicKey ): Promise <void> {
  console.clear();
  const intent = (await keys).publicKey.toJsonString();
  const j = sha.digest(intent);
  console.log("Resumen digest: " +await j);
  const msgBI = bic.base64ToBigint(await j);
  const r = bcu.randBetween((await keys).publicKey.n - 1n)
  const blindMsg = msgBI * bcu.modPow(r, (await keysCE).e, (await keysCE).n);
  const blindMsgB64 = bic.bigintToBase64(blindMsg);
  const response = await fetch("http://localhost:8080/rsa/sign", {
    method: 'POST',
    body: JSON.stringify({
      message: blindMsgB64,
    }),
    headers: {'Content-Type': 'application/json',
  } 
  });
  const data = await response.json();
  const parsedData = await (JSON.parse(JSON.stringify(data)));
  console.log ("La data devuelta del servidor es: " +await parsedData.message);
  const s = bic.base64ToBigint(await parsedData.message) *bcu.modInv(r, (await keysCE).n);
  const v = (await keysCE).verify(s);
  console.log("Después de descegar, obtengo esto al verificar la firma: "+bic.bigintToBase64(v));
  cert = bic.bigintToBase64(s);
  hascert = true;
  const answers = await inquirer.prompt({
    type: "list",
    name: "command",
    message: "Elige una opción",
    choices: Object.values(Commands2)
  });
  switch (answers["command"]) {
    case Commands2.Back:
      promptUser();
      break;
  }
}

async function cekeySee() {
  if (keysCE != undefined) {
    console.clear();
    console.log("La clave pública del CE és: "+keysCE.toJsonString());
    const answers = await inquirer.prompt({
      type: "list",
      name: "command",
      message: "Elige una opción",
      choices: Object.values(Commands2)
    });
    switch (answers["command"]) {
      case Commands2.Back:
        promptUser();
        break;
    }
  }
  else {
    console.clear();
    console.log("Aún no dispones de la clave del CE");
    const answers = await inquirer.prompt({
      type: "list",
      name: "command",
      message: "Elige una opción",
      choices: Object.values(Commands2)
    });
    switch (answers["command"]) {
      case Commands2.Back:
        promptUser();
        break;
    }
  }
}

async function sendVote(keys: RsaKeyPair, keysCE: RsaPublicKey, vote: string, pubK_user_signed: String) {
  console.clear();
  const response = await fetch("http://localhost:3000/rsa/paillierkeys", {
      method: 'POST',
      headers: {'Content-Type': 'application/json',
    } 
    });
  const data = await response.json();
  const parsedData = await (JSON.parse(JSON.stringify(await data)));
  console.log("las keys son :" + bic.base64ToBigint(parsedData.g));
  const paillierkeys = new paillierBigint.PublicKey(bic.base64ToBigint(await parsedData.n), bic.base64ToBigint(await parsedData.g));
  const encrypted_vote = paillierkeys.encrypt(bic.base64ToBigint(vote));
  console.log("voto encriptau: "+ bic.bigintToBase64(encrypted_vote));
  const vote_hash = sha.digest(bic.bigintToBase64(encrypted_vote),'SHA-256');
  console.log("hash: "+await vote_hash);
  const signed_hash_vote= keys.privateKey.sign(bic.base64ToBigint(await vote_hash));
  console.log(await bic.bigintToBase64(signed_hash_vote))
  console.log("hash vote: "+(vote_hash));
  const json = {
		pubk_user_e: bic.bigintToBase64(keys.publicKey.e),
    pubk_user_n: bic.bigintToBase64(keys.publicKey.n),
    pubK_user_signed: (await pubK_user_signed),
    encrypt_pubks: bic.bigintToBase64(await encrypted_vote),
    sign_privc: bic.bigintToBase64(await signed_hash_vote)
	}
  console.log("el json es: "+JSON.stringify(json));
  const secondRes = await fetch("http://localhost:3000/rsa/vote", {
      method: 'POST',
      body: JSON.stringify(json),
      headers: {'Content-Type': 'application/json',
    } 
    });
  const finaldata = await secondRes.json();
  const parsedfinal = await (JSON.parse(JSON.stringify(await finaldata)));
  voted = true;
  console.log( JSON.stringify(parsedfinal));
  const answers = await inquirer.prompt({
    type: "list",
    name: "command",
    message: "Elige una opción",
    choices: Object.values(Commands2)
  });
  switch (answers["command"]) {
    case Commands2.Back:
      promptUser();
      break;
  }
}

async function pickVote(): Promise<void> {
  if (voted == false && access == true) {
    if (hascert == true) {
      console.clear();
      const answers = await inquirer.prompt({
        type: "list",
        name: "command",
        message: "Mark Task Complete",
        choices: Object.values(Votacion)
        });
        switch (answers["command"]) {
          case Votacion.Laporta:
            sendVote(await keys, keysCE, "00010000", cert);
            break;
          case Votacion.Bartomeu:
            sendVote(await keys, keysCE, "00000001", cert);
            break;
          case Votacion.Back:
            promptUser();
            break;
        }
      }
      else {
        const answers = await inquirer.prompt({
          type: "list",
          name: "command",
          message: "Aún no dispones de la clave del CE",
          choices: Object.values(Commands2)
        });
        switch (answers["command"]) {
          case Commands2.Back:
            promptUser();
            break;
        }
      }
    }
    else {
      if (voted == true) {
        const answers = await inquirer.prompt({
          type: "list",
          name: "command",
          message: "Un usuario solo puede votar una vez!",
          choices: Object.values(Commands2)
        });
        switch (answers["command"]) {
          case Commands2.Back:
            promptUser();
            break;
        }
      }
      else {
        const answers = await inquirer.prompt({
          type: "list",
          name: "command",
          message: "Tienes que hacer login antes!",
          choices: Object.values(Commands2)
        });
        switch (answers["command"]) {
          case Commands2.Back:
            promptUser();
            break;
        }
      }
    }
};

async function promptUser(): Promise<void> {
  console.clear();
  displayTaskList();
  const answers = await inquirer.prompt({
    type: "list",
    name: "command",
    message: "Elige una opción",
    choices: Object.values(Commands)
  });
  switch (answers["command"]) {
    case Commands.KeySee:
      keySee();
      break;
    case Commands.CEKeySee:
      cekeySee();
      break;
    case Commands.Login:
      login();
      break;
    case Commands.GetCert:
      getCert(await keys,keysCE);
      break;
    case Commands.Vote:
      pickVote();
      break;
  }
}

const keys = keyGen();
promptUser();
