const crypto = require("crypto");
const { Module, SessionFlag, MechanismEnum, KeyGenMechanism, ObjectClass, KeyType } = require("graphene-pk11");

function main(args) {
  const lib = "/usr/local/lib/softhsm/libsofthsm2.so";

  const mod = Module.load(lib, "SoftHSMv2");
  mod.initialize();

  try {
    const slot = mod.getSlots(0, true);
    const session = slot.open(SessionFlag.SERIAL_SESSION | SessionFlag.RW_SESSION);
    session.login("12345");

    //#region Generate keys
    const id = crypto.randomBytes(20);
    const label = "RSA test key";

    const publicTemplate = {
      token: false,
      class: ObjectClass.PUBLIC_KEY,
      keyType: KeyType.RSA,
      private: false,
      label,
      id,
      verify: false,
      encrypt: false,
      wrap: false,
      // RSA params
      modulusBits: 2048,
      publicExponent: Buffer.from([1, 0, 1]),
    };
    const privateTemplate = {
      token: false,
      sensitive: false,
      class: ObjectClass.PRIVATE_KEY,
      keyType: KeyType.RSA,
      private: true,
      label,
      id: id,
      extractable: true,
      derive: false,
      sign: true,
      decrypt: false,
      unwrap: false,
    };
    const keys = session.generateKeyPair(KeyGenMechanism.RSA, publicTemplate, privateTemplate);
    console.log("RSA key generation: OK");
    //#endregion

    //#region Copy keys to token
    session.copy(keys.privateKey, { token: true });
    console.log("Copy private key:   OK");
    session.copy(keys.publicKey, { token: true });
    console.log("Copy public key:    OK");
    //#endregion
  } catch (err) {
    console.error(err);
  }

  mod.finalize();
}

main(process.argv.slice(2));