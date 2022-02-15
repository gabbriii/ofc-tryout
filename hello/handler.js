"use strict"

module.exports = async (event, context) => {
    return context
        .status(200)
        .headers({"Content-Type": "text/html"})
        .succeed(`
        <h1>
            👋 Hello World 🌍
        </h1>`);
}
