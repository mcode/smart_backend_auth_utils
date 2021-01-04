const jose = require("node-jose")
const qs = require("querystring")

class ServerUtils {

  constructor(serverConfiguration){
    this.serverConfiguration = serverConfiguration
  }

  /**
   * Get the keystore that will contain the keys used to validate BEARER Tokens
   * This will be configured from either the configuration objects jwks or jwks_uri. 
   * If the config contains a uri it will download the keys from there.
   */
  async getKeystore(){
    if(this.keystore){return this.keystore}
    if(this.serverConfiguration.jwks){
      this.keystore = jose.JWK.asKeyStore(this.serverConfiguration.jwks)
    }else if(this.serverConfiguration.jwks_uri){
      let jwks = await this.getJWKS(this.serverConfiguration.jwks_uri)
      this.keystore = await jose.JWK.asKeyStore(jwks)
    }
    return this.keystore
  }

  /**
   * Download the server's jwks from a remote location
   */
  async retrieveJWKS(){
    let response = await axios.get(this.serverConfiguration.jwks_uri)
    this.serverConfiguration.jwks = response.data
    return this.serverConfiguration.jwks 
  }


  /**
   * Validate the signature on a bearer token
   * @param {*} token 
   */
  async validateLocal(token){
    return await jose.JWS.createVerify(this.getKeystore()).verify(token)
  }


  /**
   * Perform validation of a token based on the remote server's introspection endpoint. 
   * @param {*} token 
   */
  async serverValidate(token){
    const config = {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
    let response = await axios.post(this.serverConfiguration.intorspection_endpoint, qs.stringify({token: token}), config)
    let result = response.data
    if(result.active){
      return result
    }
    return null 
  }
}

module.exports = ServerUtils