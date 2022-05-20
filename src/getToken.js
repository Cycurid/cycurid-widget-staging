const Buffer = require("buffer/").Buffer;
const fetch = require("node-fetch");
const FormData = require("form-data");

module.exports = async function getToken(code, clientID, clientSecret) {
  try {
    const data = `${clientID}:${clientSecret}`;
    let token;

    let buff = new Buffer(data);
    let base64data = buff.toString("base64");
    var myHeaders = new fetch.Headers();
    myHeaders.append("Authorization", `Basic ${base64data}`);

    var formdata = new FormData();
    formdata.append("grant_type", "authorization_code");
    formdata.append("scope", "username");
    formdata.append("code", code);

    var requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: formdata,
    };
    await fetch(`${process.env.OAUTH_SERVER}/oauth/token`, requestOptions)
      .then((response) => {
        console.log("response 1: ", response);
        response.text();
      })
      .then((res) => {
        console.log("response 2: ", res);
        return JSON.parse(res);
      })
      .then((data) => {
        console.log("response: 3", data);
        token = data.access_token;
      })
      .catch((error) => {
        console.log("error: ", error.response);
        return error;
      });

    return token;
  } catch (error) {
    return error;
  }
};
