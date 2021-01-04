const jose = require('node-jose')
const axios = require('axios')
const InMemoryPersistence = require('./in_memory_persistence')
const { v4 } = require("uuid")
const qs = require("querystring")

class Client {

  /**
   * 
   * @param {*} jwks This clients private key set used for signing requests
   * @param {*} persistence An implementation of a persistence object to cache configurations and access tokens 
   * @param {*} options addtional options
   */
  constructor(jwks, persistence = new InMemoryPersistence(), options = {}) {
    this.jwks = jwks;
    this.persistence = persistence
    this.serverKeyStores = {}
    this.signingKeyId = options.signingKeyId
    this.options = options
  }

  /**
   * Get the local keystore that contains the JWKs for this client
   */
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

  /**
   * Get the Keystore that contains the keys for a remote server.  This will check the 
   * persistence object for the keys first and return those, otherwise it will attempt 
   * retrieve the keys from the remote servers public jwks_uri. 
   * @param {*} server The base url of the server
   */
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


  /**
   * Get the key from the keystore for the kid provided.  If it is not there return
   * the first key used for signing 
   * @param {*} kid  the kid of the key to lookup
   */
  async getKeyOrDefault(kid) {
    let keystore = await this.getKeystore()
    if (kid) {
      return keystore.get(kid)
    }
    return keystore.all({ use: 'sig' })
  }

  /**
   * Generate a signed JWT used for authenticating 
   * @param {*} client_id The identifier of the client on the remote server
   * @param {*} aud The token url of the server the JWT is being created for
   * @param {*} kid The identifier of the key in the JWKS to sign the JWT
   */
  async generateJWT(client_id, aud, kid = this.signingKeyId) {
    let options = { alg: 'RS384', compact: true }
    let key = await this.getKeyOrDefault(kid)

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

  /**
   * Load the smat configuration from the remote servers /.well-known/smart-configuration uri
   * 
   * @param {*} server The base url of the remote server 
   */
  async loadServerConfiguration(server) {
    // make an http request to the /.well-known/smart-configuration url of the server
    // and store the config locally 
    let configResponse = await axios.get(server + "/.well-known/smart-configuration");
    this.persistence.addServerConfiguration(server, configResponse.data)
    await this.loadServerKeys(server)
    return configResponse.data
  }

  /**
   * Load the remote servers public keys.  This will look at the remote servers smart configuration 
   * for a pointer to the servers jwks_uri 
   * @param {*} server The base url of the server
   */
  async loadServerKeys(server) {
    let config = await this.getServerConfiguration(server);
    let response = await axios.get(config.jwks_url);
    await this.persistence.addServerKeys(server, response.data)
    return response.data
  }

  /**
   * Add a server to this client.  If serverConfig is provide it will use that as the servers
   * Configuration, otherwise it will attemt to load the configuration from the server
   * @param {*} server The base url of the server
   * @param {*} serverConfig JSON representation of the servers smart configuration 
   */
  async addServer(server, serverConfig = null) {
    this.persistence.addServer(server)
    if (serverConfig) {
      this.persistence.addServerConfiguration(serverConfig)
      return serverConfig;
    } else {
      return await this.loadServerConfiguration(server)
    }
  }

  /**
   * Add a client configuration for the remote server. 
   * @param {*} server The base url of the server
   * @param {*} client The client meta-data from registering the client
   */
  async addClientConfiguration(server, client) {
    return await this.persistence.addClientConfiguration(server, client)
  }

  /**
   * Add the remote servers configuration 
   * @param {*} server The base url of the server
   * @param {*} config  The smar configruation json for the server
   */
  async addServerConfiguration(server, config) {
    return await this.persistence.addServerConfiguration(server, config)
  }

  /**
   * 
   * @param {*} server The base url of the server
   */
  async getServerConfiguration(server) {
    return await this.persistence.getServerConfiguration(server)
  }

  /**
   * Get the client configuration for the given server
   * @param {*} server The base url of the server
   */
  async getClientConfiguration(server) {
    return await this.persistence.getClientConfiguration(server)
  }

  /**
   * Get a cached access token for the remote server
   * @param {*} server The base url of the server
   */
  async getAccessToken(server) {
    return await this.persistence.getAccessToken(server)
  }

  /**
   * Add and cache an access token for the remote server 
   * @param {*} server The base url of the server
   * @param {*} token the token to cache
   */
  async addAccessToken(server, token) {
    await this.persistence.addAccessToken(server, token)
  }

  /**
   * Get the scopes set for this client to request from remote servers
   */
  scopes() {
    return this.options.scopes || 'system/*.read'
  }


  /**
   * Request an access token from a remote server
   * @param {*} server The base url of the server to request a token from
   * @param {*} kid the identifier of the key to use for signing the token request
   * @param {*} scopes the scopes to request access for
   */
  async requestAccessToken(server, kid = this.signingKeyId, scopes = this.scopes()) {
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

/**
 * Generate the data needed to send to a remote server for dynamically registering a client
 */
  generateRegistrationMetaData() {
    let config = {
      "client_name": this.options.client_name,
      "token_endpoint_auth_method": "client_credentials"
    }

    // add either the uri for the clients public keys or add the keys directly
    if (this.options.jwks_uri) {
      config.jwks_uri = this.options.jwks_uri
    } else {
      config.jwks = this.jwks
    }
    return config
  }


  /**
   * Perform dynamic client registration on the server
   * @param {*} server The base url of the remote server
   * 
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

  /**
   * Class method to generate JWKS
   * @param {*} params 
   */
  static async generateJWKS(params) {
    return await jose.JWK.createKey("oct", 384, { alg: "RS256" })
  }
}



module.exports = { Client: Client }