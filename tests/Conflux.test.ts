import { test, expect, describe } from "vitest";
import {
  openTransportReplayer,
  RecordStore,
} from "@ledgerhq/hw-transport-mocker";
import Conflux from "../src/Conflux";

describe("getAddress", () => {
  test("default", async () => {
    const transport = await openTransportReplayer(
      RecordStore.fromString(`
      => e002000015058000002c800001f7800000000000000000000000
      <= 41042b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b9000
      `)
    );
    const cfx = new Conflux(transport, 1);
    const result = await cfx.getAddress("44'/503'/0'/0/0");

    expect(result).toEqual({
      address: "cfxtest:aaknjd0mgxtp559wae49m1224a319vfedpt17b1ayu",
      publicKey:
        "2b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b",
    });
  });

  test("boolDisplay", async () => {
    const transport = await openTransportReplayer(
      RecordStore.fromString(`
      => e002010019058000002c800001f780000000000000000000000000000001
      <= 41042b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b9000
      `)
    );
    const cfx = new Conflux(transport, 1);
    const result = await cfx.getAddress("44'/503'/0'/0/0", true);
    expect(result).toEqual({
      address: "cfxtest:aaknjd0mgxtp559wae49m1224a319vfedpt17b1ayu",
      publicKey:
        "2b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b",
    });
  });

  test("boolChaincode", async () => {
    const transport = await openTransportReplayer(
      RecordStore.fromString(`
      => e002000115058000002c800001f7800000000000000000000000
      <= 41042b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b2084fbde4aa4d21a1572a117ce29129a1eee64e2bf3fe7e522a2d55acf0fb3c44c9000
      `)
    );

    const cfx = new Conflux(transport, 1);
    const result = await cfx.getAddress("44'/503'/0'/0/0", false, true);
    expect(result).toEqual({
      chainCode:
        "84fbde4aa4d21a1572a117ce29129a1eee64e2bf3fe7e522a2d55acf0fb3c44c",
      address: "cfxtest:aaknjd0mgxtp559wae49m1224a319vfedpt17b1ayu",
      publicKey:
        "2b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b",
    });
  });

  test("all options", async () => {
    const transport = await openTransportReplayer(
      RecordStore.fromString(`
      => e002010119058000002c800001f780000000000000000000000000000001
      <= 41042b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b2084fbde4aa4d21a1572a117ce29129a1eee64e2bf3fe7e522a2d55acf0fb3c44c9000
      `)
    );

    const cfx = new Conflux(transport, 1);
    const result = await cfx.getAddress("44'/503'/0'/0/0", true, true);
    expect(result).toEqual({
      chainCode:
        "84fbde4aa4d21a1572a117ce29129a1eee64e2bf3fe7e522a2d55acf0fb3c44c",
      address: "cfxtest:aaknjd0mgxtp559wae49m1224a319vfedpt17b1ayu",
      publicKey:
        "2b6d8aa81a075392901ff2166722f035d9dc719da33f86a75dbf9b7af0306f19bdd7cfe2de6c19bf994bdc7a8009dceb1d3cb9c1e10e76bf40d8f19acdc4518b",
    });
  });
});

test("getAppConfiguration (v1)", async () => {
  const transport = await openTransportReplayer(
    RecordStore.fromString(`
      => b001000000
      <= 0107436f6e666c757805312e302e3001029000
      `)
  );

  const cfx = new Conflux(transport, 1029);
  const result = await cfx.getAppConfiguration();
  expect(result.name).toEqual("Conflux");
  expect(result.version).toEqual("1.0.0");
});

describe("signTransaction", () => {
  test("legacy", async () => {
    const transport = await openTransportReplayer(
      RecordStore.fromString(`
        => b001000000
        <= 0107436f6e666c757805312e302e3001029000
        => e003000045058000002c800001f7800000000000000000000000ef37843b9aca008252089412b40eca34decdeff20135f55f18d0337fc4a41b880de0b6b3a764000080840ba20e290180
        <= 017277a9b9dc46074376942205d454ffb3e233488f970cbac1d0bafa148b53ec8b19ea2fd14f0f1e7fae32b9d21410b85be0f620b1e785901d362265a73ca304ec9000
        `)
    );

    const cfx = new Conflux(transport, 1);
    const result = await cfx.signTransaction(
      "44'/503'/0'/0/0",
      "ef37843b9aca008252089412b40eca34decdeff20135f55f18d0337fc4a41b880de0b6b3a764000080840ba20e290180"
    );

    expect(result).toEqual({
      v: "1",
      r: "7277a9b9dc46074376942205d454ffb3e233488f970cbac1d0bafa148b53ec8b",
      s: "19ea2fd14f0f1e7fae32b9d21410b85be0f620b1e785901d362265a73ca304ec",
    });
  });
});

describe("signTransaction", () => {
  test("legacy", async () => {
    // https://testnet.confluxscan.io/transaction/0xa04db7de586f44faf31c9888bd0d9b0dc3beba7b0a7c492f6d95ef241fbe6156
    const transport = await openTransportReplayer(
      RecordStore.fromString(`
        => b001000000
        <= 0107436f6e666c757805312e302e3001029000
        => e003000045058000002c800001f7800000000000000000000000ef38843b9aca008252089412b40eca34decdeff20135f55f18d0337fc4a41b88016345785d8a000080840ba2223c0180
        <= 0014f46ab4a44d33413059cd4da08e729c0223afe65d9aaf702086d50877a38ce329fa045635f57d9cd85594221c864d086a4bebe722aaf37078bbe7c52b46b15d9000
        `)
    );

    const cfx = new Conflux(transport, 1);

    const result = await cfx.signTransaction(
      "44'/503'/0'/0/0",
      "ef38843b9aca008252089412b40eca34decdeff20135f55f18d0337fc4a41b88016345785d8a000080840ba2223c0180"
    );

    expect(result).toEqual({
      r: "14f46ab4a44d33413059cd4da08e729c0223afe65d9aaf702086d50877a38ce3",
      s: "29fa045635f57d9cd85594221c864d086a4bebe722aaf37078bbe7c52b46b15d",
      v: "0",
    });
  });

  test("1559", async () => {
    // https://testnet.confluxscan.io/transaction/0x43e7852b06d0d3de51fd3d216ff7ed66bf1d61802ed50422147a09d6cf5e8c33
    // todo update getAppConfiguration response
    const transport = await openTransportReplayer(
      RecordStore.fromString(`
        => b001000000
        <= 0107436f6e666c75780001029000
        => e003008015058000002c800001f7800000000000000000000000
        <= 9000
        => e00301003a63667802f5618401c9c380843d648d80825208941d5f42dcba6d639055cceedc83dc5056b4020fcc88016345785d8a000080840ba223cb0180c0
        <= 00a3e04e20e01b634a55944296993afbe7217527ea0dae487e6cecc04af2dfa34977841fae3ee030412f3a77a6e19db7c2515fffcb814c488655d1dabb89c7e0939000
        `)
    );

    const cfx = new Conflux(transport, 1);

    const result = await cfx.signTransaction(
      "44'/503'/0'/0/0",
      "63667802f5618401c9c380843d648d80825208941d5f42dcba6d639055cceedc83dc5056b4020fcc88016345785d8a000080840ba223cb0180c0"
    );
    expect(result).toEqual({
      r: "a3e04e20e01b634a55944296993afbe7217527ea0dae487e6cecc04af2dfa349",
      s: "77841fae3ee030412f3a77a6e19db7c2515fffcb814c488655d1dabb89c7e093",
      v: "0",
    });
  });
});
