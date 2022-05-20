const axios = require('axios')

module.exports = async function axiosRequest(method, url, body = null, headers = {}) {
    return await axios({
      method,
      url,
      data: body,
      headers,
    })
      .then((response) => {
        return response.data
      })
      .catch((error) => {
        // Error handling here
  
        // Responded with non-2xx error code
        if (error.response) {
        } else if (error.request) {
          // The request was made but no response was received
          // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
          // http.ClientRequest in node.js
        } else {
        }
  
        // Pass out the error for error handling
        throw error
      })
  }