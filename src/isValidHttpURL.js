module.exports = function isValidHttpUrl(string) {
  let url;

  try {
    url = new URL(string);
  } catch (_) {
    return false;
  }

  if (url.protocol === "http:" || url.protocol === "https:") {
    return string.match(/\.(com|ca|co|org|net)/) != null;
  }
  return false;
};
