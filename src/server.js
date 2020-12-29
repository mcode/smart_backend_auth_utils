
const jose = require("node-jose")
const qs = require("querystring")
class ServerUtils {

  constructor(serverConfiguration){
    this.serverConfiguration = serverConfiguration
  }


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

  async retrieveJWKS(url){
    let response = await axios.get(this.serverConfiguration.jwks_uri)
    this.serverConfiguration.jwks = response.data
    return this.serverConfiguration.jwks 
  }


  async validateLocal(token){
    return await jose.JWS.createVerify(this.getKeystore()).verify(token)
  }


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