const isValidHttpUrl = require("./isValidHttpURL");

module.exports = function checkParams(data, onSuccess, onFailure) {
  try {
    if (!data.action) {
      throw { statusText: "action is required" };
    }
    if (!data.client_id) {
      throw { statusText: "client_id is required" };
    }
    if (!data.client_secret) {
      throw { statusText: "client_secret is required" };
    }
    if (!data.redirect_url) {
      throw { statusText: "redirect_url is required" };
    }
    if (!data.scope) {
      throw { statusText: "scope is required" };
    }

    if (!onSuccess || typeof onSuccess !== "function") {
      throw { statusText: "onSuccess function is required" };
    }
    if (!onFailure || typeof onSuccess !== "function") {
      throw { statusText: "onFailure function is required" };
    }

    const valid = isValidHttpUrl(data.redirect_url);

    if (valid) {
      return true;
    } else {
      throw { statusText: "Invalid URL" };
    }
  } catch (error) {
    throw error;
  }
};
