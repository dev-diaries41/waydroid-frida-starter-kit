const express = require('express');
const app = express();
const port = 3000;

app.use(express.json());
app.post('/intercept', (req, res) => {
    try {
        res.status(200).json({receivedBody: req.body, receivedParams: req.params, receivedQueries: req.query});
    } catch (error) {
        res.status(500).json({message: "Internal server error"});
    }
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
