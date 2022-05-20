const axiosRequest = require("./src/axiosRequest");
const checkParams = require("./src/checkParams");
const Buffer = require("buffer/").Buffer;
const fetch = require("node-fetch");
const FormData = require("form-data");

const OAUTH_SERVER = "https://api.cycurid.com";
const IMMEWIDGET_URL = `http://localhost:3000`;

async function immeCompleteOauth(data, onSuccess, onFailure) {
  try {
    checkParams(data, onSuccess, onFailure);
    const widget = `${IMMEWIDGET_URL}?client_id=${data.client_id}&redirect_url=${data.redirect_url}&scope=${data.scope}&action=${data.action}`;
    window.open(widget);
    window.addEventListener("message", async (event) => {
      if (event.origin !== IMMEWIDGET_URL) {
        return;
      } else {
        const token = await getToken({
          code: event.data.code,
          client_id: data.client_id,
          client_secret: data.client_secret,
        });
        if (token.status && token.status !== 200) {
          onFailure(token);
        } else {
          const userInfo = await getUserInfo(token.access_token);
          onSuccess(userInfo);

          const refresh_token = await refreshToken({
            token: token.refresh_token,
            client_id: data.client_id,
            client_secret: data.client_secret,
          });

          console.log(refresh_token);

          const revoke_token = await revokeToken({
            token: refresh_token.access_token,
            client_id: data.client_id,
            client_secret: data.client_secret,
          });

          console.log(revoke_token);
        }
      }
    });
  } catch (error) {
    onFailure(error);
  }
}

// error handling on getuserinfo <=========

async function getCode(data, onSuccess, onFailure) {
  try {
    checkParams(data, onSuccess, onFailure);
    const widget = `${IMMEWIDGET_URL}?client_id=${data.client_id}&redirect_url=${data.redirect_url}&scope=${data.scope}&action=${data.action}`;
    window.open(widget);
    window.addEventListener("message", async (event) => {
      if (event.origin !== IMMEWIDGET_URL) {
        return;
      } else {
        onSuccess(event.data);
      }
    });
  } catch (error) {
    onFailure(error);
  }
}

// need revoke token
async function revokeToken(data) {
  try {
    if (!data.token) {
      throw { statusText: "Missing token" };
    }
    if (!data.client_id) {
      throw { statusText: "Missing client_id" };
    }
    if (!data.client_secret) {
      throw { statusText: "Missing client_secret" };
    }

    const info = `${data.client_id}:${data.client_secret}`;
    let response;

    let buff = new Buffer(info);
    let base64data = buff.toString("base64");
    var myHeaders = new fetch.Headers();
    myHeaders.append("Authorization", `Basic ${base64data}`);

    var formdata = new FormData();
    formdata.append("token", data.token);

    var requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: formdata,
    };
    await fetch(`${OAUTH_SERVER}/oauth/revoke`, requestOptions)
      .then((response) => {
        if (response.status !== 200) {
          throw response;
        }
        return response.text();
      })
      .then((res) => {
        return JSON.parse(res);
      })
      .then((data) => {
        response = data;
      })
      .catch((error) => {
        throw error;
      });

    return response;
  } catch (error) {
    console.log(error.response);
    if (error.status) {
      return {
        status: error.status,
        statusText: error.statusText,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

async function getUserInfo(token) {
  try {
    if (!token) {
      throw { statusText: "Token is required." };
    }
    return await axiosRequest(
      "get",
      // `${OAUTH_SERVER}/oauth/userinfo`,
      `${OAUTH_SERVER}/v1/public/users/resources/get_info`,
      {},
      {
        Authorization: `Bearer ${token}`,
      }
    );
  } catch (error) {
    if (error.response.status) {
      return {
        status: error.response.status,
        statusText: error.response.statusText,
        message: error.response.data.message,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

async function getToken(data) {
  try {
    if (!data.code) {
      throw { statusText: "Missing code" };
    }
    if (!data.client_id) {
      throw { statusText: "Missing client_id" };
    }
    if (!data.client_secret) {
      throw { statusText: "Missing client_secret" };
    }

    const info = `${data.client_id}:${data.client_secret}`;
    let response;

    let buff = new Buffer(info);
    let base64data = buff.toString("base64");
    var myHeaders = new fetch.Headers();
    myHeaders.append("Authorization", `Basic ${base64data}`);

    var formdata = new FormData();
    formdata.append("grant_type", "authorization_code");
    formdata.append("scope", "username");
    formdata.append("code", data.code);

    var requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: formdata,
    };
    await fetch(`${OAUTH_SERVER}/oauth/token`, requestOptions)
      .then((response) => {
        if (response.status !== 200) {
          throw response;
        }
        return response.text();
      })
      .then((res) => {
        return JSON.parse(res);
      })
      .then((data) => {
        response = data;
      })
      .catch((error) => {
        throw error;
      });

    return response;
  } catch (error) {
    if (error.status) {
      return {
        status: error.status,
        statusText: error.statusText,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

async function refreshToken(data) {
  try {
    if (!data.token) {
      throw { statusText: "Missing token" };
    }
    if (!data.client_id) {
      throw { statusText: "Missing client_id" };
    }
    if (!data.client_secret) {
      throw { statusText: "Missing client_secret" };
    }

    const info = `${data.client_id}:${data.client_secret}`;
    let response;

    let buff = new Buffer(info);
    let base64data = buff.toString("base64");
    var myHeaders = new fetch.Headers();
    myHeaders.append("Authorization", `Basic ${base64data}`);

    var formdata = new FormData();
    formdata.append("grant_type", "refresh_token");
    formdata.append("refresh_token", data.token);

    var requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: formdata,
    };

    await fetch(`${OAUTH_SERVER}/oauth/token`, requestOptions)
      .then((response) => {
        if (response.status !== 200) {
          throw response;
        }
        return response.text();
      })
      .then((res) => {
        return JSON.parse(res);
      })
      .then((data) => {
        response = data;
      })
      .catch((error) => {
        throw error;
      });

    return response;
  } catch (error) {
    if (error.status) {
      return {
        status: error.status,
        statusText: error.statusText,
      };
    }
    return {
      statusText: error.statusText,
    };
  }
}

module.exports = {
  immeCompleteOauth,
  getCode,
  getUserInfo,
  getToken,
  refreshToken,
  revokeToken,
};
