module.exports = class InMemoryPersistence {


  constructor(cache = {
    servers: [],
    serverConfig: {},
    clientConfig: {},
    accessTokens: {},
    serverKeys: {}
  }) {
    this.cache = cache;
  }

  addServer(server) {
    this.cache.servers.push(server)
  }

  addServerConfiguration(server, config) {
    this.cache.servers[server] = config
  }

  getServerConfiguration(server) {
    return this.cache.servers[server]
  }

  addClientConfiguration(server, client) {
    this.cache.clientConfig[server] = client
  }

  getClientConfiguration(server) {
    return this.cache.clientConfig[server]
  }

  addAccessToken(server, token) {
    this.cache.accessTokens[server] = token
  }

  getAccessToken(server) {
    return this.cache.accessTokens[server]
  }

  getServerKeys(server){
    let keys = this.cache.serverKeys[server];
    if(!keys && this.getServerConfiguration(server)){
      keys =  this.getServerConfiguration(server).jwks
    }
    return keys;
  }

  addServerKeys(server, keys){
    this.cache.serverKeys[server] = keys
  }
  clearTokens(server) {
    if (!server) {
      this.cache.accessTokens = {}
    }
    else {
      delete this.cache.accessTokens[server]
    }
  }
}