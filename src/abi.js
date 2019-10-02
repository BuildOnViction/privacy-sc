var abi = [
    {
      "constant": true,
      "inputs": [
        {
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "keyImages",
      "outputs": [
        {
          "name": "",
          "type": "bool"
        }
      ],
      "payable": false,
      "stateMutability": "view",
      "type": "function"
    },
    {
      "payable": true,
      "stateMutability": "payable",
      "type": "fallback"
    },
    {
      "constant": false,
      "inputs": [
        {
          "name": "_commitment",
          "type": "bytes1[33]"
        },
        {
          "name": "_pubkey",
          "type": "bytes1[33]"
        },
        {
          "name": "_amount",
          "type": "bytes1[32]"
        },
        {
          "name": "_mask",
          "type": "bytes1[32]"
        }
      ],
      "name": "deposit",
      "outputs": [],
      "payable": true,
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "constant": false,
      "inputs": [
        {
          "name": "proof",
          "type": "bytes1[]"
        }
      ],
      "name": "privateSend",
      "outputs": [],
      "payable": false,
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "constant": false,
      "inputs": [
        {
          "name": "recipient",
          "type": "address"
        },
        {
          "name": "_amount",
          "type": "uint256"
        },
        {
          "name": "proof",
          "type": "bytes1[]"
        }
      ],
      "name": "withdrawFunds",
      "outputs": [],
      "payable": false,
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "constant": true,
      "inputs": [
        {
          "name": "index",
          "type": "uint256"
        }
      ],
      "name": "getUTXO",
      "outputs": [
        {
          "name": "",
          "type": "bytes1[33]"
        },
        {
          "name": "",
          "type": "bytes1[33]"
        },
        {
          "name": "amount",
          "type": "bytes32"
        },
        {
          "name": "blind",
          "type": "bytes32"
        }
      ],
      "payable": false,
      "stateMutability": "view",
      "type": "function"
    }
  ]