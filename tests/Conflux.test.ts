import {
  openTransportReplayer,
  RecordStore,
} from "@ledgerhq/hw-transport-mocker";
import Conflux from "../src/Conflux";

test("getAddress", async () => {
  const transport = await openTransportReplayer(
    RecordStore.fromString(`
    => e002000015058000002c8000003c800000008000000000000000
    <= 4104df00ad3869baad7ce54f4d560ba7f268d542df8f2679a5898d78a690c3db8f9833d2973671cb14b088e91bdf7c0ab00029a576473c0e12f84d252e630bb3809b28436241393833363265313939633431453138363444303932334146393634366433413634383435319000
    `)
  );
  const cfx = new Conflux(transport);
  const result = await cfx.getAddress("44'/503'/0'/0'/0");

  expect(result).toEqual({
    address: "0xCbA98362e199c41E1864D0923AF9646d3A648451",
    publicKey:
      "04df00ad3869baad7ce54f4d560ba7f268d542df8f2679a5898d78a690c3db8f9833d2973671cb14b088e91bdf7c0ab00029a576473c0e12f84d252e630bb3809b",
  });
});

test("signTransaction", async () => {
  const transport = await openTransportReplayer(
    RecordStore.fromString(`
    => e00400003e058000002c8000003c800000008000000000000000e8018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a2487400080
    <= 1b3694583045a85ada8d15d5e01b373b00e86a405c9c52f7835691dcc522b7353b30392e638a591c65ed307809825ca48346980f52d004ab7a5f93657f7e62a4009000
    `)
  );
  const cfx = new Conflux(transport);
  const result = await cfx.signTransaction(
    "44'/503'/0'/0'/0",
    "e8018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a2487400080"
  );
  expect(result).toEqual({
    r: "3694583045a85ada8d15d5e01b373b00e86a405c9c52f7835691dcc522b7353b",
    s: "30392e638a591c65ed307809825ca48346980f52d004ab7a5f93657f7e62a400",
    v: "1b",
  });
});
