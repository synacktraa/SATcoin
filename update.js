
// dynamically update upcoming CTFs section using JSON file 
// retrieved from ctftime's rss feed.

const block = import('./block.json', {
    assert: {
        type: 'json'
    }
});


//loading block 
block.then(response => document.write(response)
);