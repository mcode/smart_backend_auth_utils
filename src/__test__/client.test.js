let { Client } = require('../client.js')
let jwks = require("./jwks.json")
let smartConfig = require("./smart-config.json")
let serverKeys = require("./server-keys.json")
let nock = require("nock")
let registeredClientConfig = require("./registered_client.json")
let accessToken = require("./access_token.json")
describe("Backend Service Client", () => {

  it("Should create an InMemoryPersistence object if persistence is not provided", async (done) => {
    let client = new Client(jwks)
    expect(client.persistence)
    done()
  })

  it("Should be able to generate a JWKS", async (done) => {
    let jwks = await Client.generateJWKS();
    console.log(jwks)
    expect(jwks)
    done()
  })

  it("Should be able to add Server Configurations manually ", async (done) => {
    let client = new Client(jwks)
    let server = "http://test.com"
    let config = {}
    client.addServerConfiguration(server, {})
    expect(await client.getServerConfiguration(server)).toEqual(config)
    done()
  })

  it("Should be able to add Client Configurations manually", async (done) => {
    let client = new Client(jwks)
    let server = "http://test.com"
    let config = {}
    client.addClientConfiguration(server, {})
    expect(await client.getClientConfiguration(server)).toEqual(config)
    done()
  })

  it("Should be able to generate a signed JWT Token Request", async (done) => {
    let client = new Client(jwks)
    let signedJWT = await client.generateJWT("Test", "http://test.com", "test")
    expect(signedJWT)
    done()
  })



  describe("remote interactions", () => {

    beforeEach(() => {

      let n = nock('https://test.com')

      n.get('/.well-known/smart-configuration')
        .reply(200, smartConfig);

      n.get("/jwks")
        .reply(200, serverKeys)

      n.post("/auth/token").reply(200, accessToken)
      n.post("/auth/register").reply(200, registeredClientConfig)
    });

    it("Should be able to retrieve a remote servers configuration", async (done) => {
      let client = new Client(jwks);
      await client.addServer("https://test.com")
      let config = await client.getServerConfiguration("https://test.com")
      expect(config).toEqual(smartConfig);
      done();
    });

    it("Should be able to register itself with a remote backend server and obtain it's client configuration information (client_id) ", async (done) => {
      let client = new Client(jwks);
      let server = "https://test.com"
      await client.addServer(server)
      await client.register(server)
      expect(await client.getClientConfiguration(server)).toEqual(registeredClientConfig)
      done()
    })


    it("Should be able to request and access_tokens for a server", async (done) => {
      let client = new Client(jwks);
      let server = "https://test.com"
      await client.addServer(server)
      await client.register(server)
      let token = await client.requestAccessToken(server, 'test')
      delete token.issued_at
      expect(token).toEqual(accessToken)
      expect(await client.getAccessToken(server)).toEqual(accessToken)
      done()
    })
  })

})