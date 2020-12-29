const jose = require('node-jose')
const axios = require('axios')
const InMemoryPersistence = require('./in_memory_persistence')
const { v4 } = require("uuid")
const qs = require("querystring")

class Client {

  constructor(jwks, persistence = new InMemoryPersistence(), options = {}) {
    this.jwks = jwks;
    this.persistence = persistence
    this.serverKeyStores = {}
    this.signingKeyId = options.signingKeyId
    this.options = options
  }

  async getKeystore() {
    if (this.keystore) { return this.keystore }
    if (this.jwks.keys) {
      this.keystore = await jose.JWK.asKeyStore(this.jwks)
      console.log(this.keystore);

    } else {
      this.keystore = jose.JWK.createKeyStore()
      this.keystore.add(this.jwks)
    }
    return this.keystore;
  }

  async getServerKeystore(server) {
    let serverKS = this.serverKeyStores[server]
    if (!serverKS) {
      let serverKeys = this.persistence.getServerKeys(server)
      if (!serverKeys) {
        serverKeys = await this.loadServerKeys(server)
      }
      let serverKS = jose.JWK.createKeyStore();
      serverKS.add(serverKeys)
      this.serverKeyStores[server] = serverKS;
    }
    return serverKS;
  }

  async getKeyOrDefault(kid) {
    console.log(kid);

    let keystore = await this.getKeystore()
    if (kid) {
      return keystore.get(kid)
    }
    return keystore.all({ use: 'sig' })
  }

  async generateJWT(client_id, aud, kid = this.signingKeyId) {
    let options = { alg: 'RS384', compact: true }
    let key = await this.getKeyOrDefault(kid)
    console.log(key);

    let input = JSON.stringify({
      sub: client_id,
      iss: client_id,
      aud: aud,
      exp: (Math.floor(Date.now() / 1000) + 300),
      jti: v4()
    })

    return await jose.JWS.createSign(options, key).
      update(input).
      final()
  }

  async loadServerConfiguration(server) {
    // make an http request to the /.well-known/smart-configuration url of the server
    // and store the config locally 
    let configResponse = await axios.get(server + "/.well-known/smart-configuration");
    console.log(configResponse.data);

    this.persistence.addServerConfiguration(server, configResponse.data)
    await this.loadServerKeys(server)
    return configResponse.data
  }

  async loadServerKeys(server) {
    let config = await this.getServerConfiguration(server);
    let response = await axios.get(config.jwks_url);
    await this.persistence.addServerKeys(server, response.data)
    return response.data
  }

  async addServer(server, serverConfig = null) {
    this.persistence.addServer(server)
    if (serverConfig) {
      this.persistence.addServerConfiguration(serverConfig)
      return serverConfig;
    } else {
      console.log(server + "/.well-known/smart-configuration");
      return await this.loadServerConfiguration(server)
    }
  }

  async addClientConfiguration(server, client) {
    return await this.persistence.addClientConfiguration(server, client)
  }

  async addServerConfiguration(server, config) {
    return await this.persistence.addServerConfiguration(server, config)
  }

  async getServerConfiguration(server) {
    return await this.persistence.getServerConfiguration(server)
  }

  async getClientConfiguration(server) {
    return await this.persistence.getClientConfiguration(server)
  }

  async getAccessToken(server) {
    return await this.persistence.getAccessToken(server)
  }

  async addAccessToken(server, token) {
    await this.persistence.addAccessToken(server, token)
  }

  scopes() {
    return this.options.scopes || 'system/*.read'
  }


  async requestAccessToken(server, kid = null, scopes = this.scopes()) {
    // see if there is an access token that is still good and send that back if so
    let accessToken = await this.getAccessToken(server)
    if (accessToken && (accessToken.issued_at + accessToken.expires_in) > (Date.now() / 1000)) {
      return accessToken;
    }
    let serverConfig = this.persistence.getServerConfiguration(server)
    let client = this.persistence.getClientConfiguration(server)

    //If the client configuration does not exist try to self register the client
    if (!client && serverConfig.registration_endpoint) {
      client = await this.register(server);
    }
    // if the client configuration exists try to get an access token 
    if (client) {
      let jwt = await this.generateJWT(client.client_id, serverConfig.token_endpoint, kid)
      let params = {
        client_assertion: jwt,
        client_assertion_type: '',
        grant_type: 'client_credentials',
        scopes: scopes
      }
      const config = {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }

      let response = await axios.post(serverConfig.token_endpoint, qs.stringify(params), config)
      let token = response.data
      token.issued_at = Date.now() / 1000
      await this.addAccessToken(server, token)
      return token
    }
    else {
      throw "Client information not found"
    }


  }

  // validates the token signature and experiation time on the token 
  async validateAccessToken(server, token) {
    // get the server keys 
    let serverKeystore = this.getServerKeystore(server)
    let verify = await jose.JWS.createVerify(serverKeystore).verify(token)
    return verify
  }

  async requestToken(server, force = false) {
    // check to see if we have a valid access token for the server
    let accessToken = await this.getAccessToken(server)
    return accessToken ? accessToken : await this.requestAccessToken(server)
  }


  generateRegistrationMetaData() {
    let config = {
      "client_name": this.options.client_name,
      "token_endpoint_auth_method": "client_credentials"
    }

    if (this.options.jwks_uri) {
      config.jwks_uri = "https://client.example.org/my_public_keys.jwks"
    } else {
      config.jwks = this.jwks
    }
    return config
  }
  /**
   * 
   * @param {*} server 
   * Perform dynamic client registration on the server
   */
  async register(server) {
    let config = await this.getClientConfiguration(server)
    if (config) {
      return config
    } else {
      let serverConfig = await this.getServerConfiguration(server)
      if (!serverConfig.registration_endpoint) {
        console.log("Registration not enabled at server ", server); ß
        return null
      } else {
        let response = await axios.post(serverConfig.registration_endpoint, this.generateRegistrationMetaData())
        await this.addClientConfiguration(server, response.data)
        return response.data;
      }
    }
  }

  static async generateJWKS(params) {
    return await jose.JWK.createKey("oct", 384, { alg: "RS256" })
  }
}



module.exports = { Client: Client }