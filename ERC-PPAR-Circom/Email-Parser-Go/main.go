package dkim

/*----------------------------------------------------------------------------------------*/
//                                                                                        //
//                                   IMPORTANT NOTE                                       //
//                                                                                        //
/*----------------------------------------------------------------------------------------*/
// This is a test file for the email parser. It is used to test the email parser and the  //
// email signature verification.                                                          //
// It is very important to note that this is not a complete implementation of the email   //
// parser and the email signature verification.                                           //
// Another note is that this file uses dkim package in Go. But the dkim package cannot    //
// imported since it does not provide all needed functions publicly.                      //
// Therefore, a copy of all the dkim package is provided in this directory.               //
//                                                                                        //
// Also, note that this file only parses the email to the correct format for our circuits //
// It does not verify the email signature.                                                //
//                                                                                        //
/*----------------------------------------------------------------------------------------*/

	import (
		"crypto"
		"crypto/rsa"
		"math/big"
		"fmt"
		"strings"

		"crypto/subtle"
		

		"bufio"
		"io"
		"encoding/json"
		"os"
		"bytes"
	)
	
	
	
	// --- Test Data Setup ---
	var (
		Email = func() string {
			data, err := os.ReadFile("../Example/Raw-Email.tx")
			if err != nil {
				panic(fmt.Sprintf("Failed to read ../Example/Raw-Email.tx: %v", err))
			}
			return string(data)
		}()
		
	)
	
	func EmailSignatureVerification() {
		sigArray := new(big.Int)
		googlePubKeyN := new(big.Int)
		googlePubKeyE := new(big.Int)

		headerHelper := []byte{}
		headerHash := []byte{}
		body := []byte{}
		bodyHashed := []byte{}


		r := strings.NewReader(Email)

		bufr := bufio.NewReader(r)
		h, _ := readHeader(bufr)
		
	

		var signatures []*signature
		for i, kv := range h {
			k, v := parseHeaderField(kv)
			if strings.EqualFold(k, headerFieldName) {
				signatures = append(signatures, &signature{i, v})
			}
		}

		if len(signatures) == 1 {
			// If there is only one signature - just verify it.
			sigValue := signatures[0].v
			sigField := h[signatures[0].i]
			
			params, err := parseHeaderParams(sigValue)

			domain := params["d"]
			selector := params["s"]


			if err != nil {
				return 
			}

		
			if params["v"] != "1" {
				return 
			}
		
		
			headerKeys := parseTagList(params["h"])
			ok := false
			for _, k := range headerKeys {
				if strings.EqualFold(k, "from") {
					ok = true
					break
				}
			}
			
			if !ok {
				return 
			}
		
			// Query public key
			methods := []string{string(QueryMethodDNSTXT)}
			if methodsStr, ok := params["q"]; ok {
				methods = parseTagList(methodsStr)
			}
			var res *queryResult
			for _, method := range methods {
				if query, ok := queryMethods[QueryMethod(method)]; ok {
					res, err = query(domain, stripWhitespace(selector), nil)
					break
				}
			}
			verif := res.Verifier.Public().(*rsa.PublicKey)
			googlePubKeyN = verif.N
			googlePubKeyE = big.NewInt(int64(verif.E))

			
			

		
			// Parse algos
			keyAlgo, hashAlgo, ok := strings.Cut(stripWhitespace(params["a"]), "-")
			if !ok {
				return //verif, permFailError("malformed algorithm name")
			}
			
			// Check hash algo
			if res.HashAlgos != nil {
				ok := false
				for _, algo := range res.HashAlgos {
					if algo == hashAlgo {
						ok = true
						break
					}
				}
				if !ok {
					return //verif, permFailError("inappropriate hash algorithm")
				}
			}
			var hash crypto.Hash
			switch hashAlgo {
			case "sha1":
				// RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for signing or
				// verifying.
				return //verif, permFailError("hash algorithm too weak")
			case "sha256":
				hash = crypto.SHA256
			default:
				return //verif, permFailError("unsupported hash algorithm")
			}

			// Check key algo
			if res.KeyAlgo != keyAlgo {
				return //verif, permFailError("inappropriate key algorithm")
			}
		
			if res.Services != nil {
				ok := false
				for _, s := range res.Services {
					if s == "email" {
						ok = true
						break
					}
				}
				if !ok {
					return //verif, permFailError("inappropriate service")
				}
			}
		
			headerCan, bodyCan := parseCanonicalization(params["c"])
			
			if _, ok := canonicalizers[headerCan]; !ok {
				return //verif, permFailError("unsupported header canonicalization algorithm")
			}
			if _, ok := canonicalizers[bodyCan]; !ok {
				return //verif, permFailError("unsupported body canonicalization algorithm")
			}
		
			// The body length "l" parameter is insecure, because it allows parts of
			// the message body to not be signed. Reject messages which have it set.
			if _, ok := params["l"]; ok {
				// TODO: technically should be policyError
				return //verif, failError("message contains an insecure body length tag")
			}
		
			// Parse body hash and signature
			bodyHashed, err = decodeBase64String(params["bh"])

			if err != nil {
				return //verif, permFailError("malformed body hash: " + err.Error())
			}
			sig, err := decodeBase64String(params["b"])
			sigArray = new(big.Int).SetBytes(sig)
			if err != nil {
				return //verif, permFailError("malformed signature: " + err.Error())
			}

			// Check body hash
			var canonBodyBuf bytes.Buffer
			hasher := hash.New()
			multiWriter := io.MultiWriter(hasher, &canonBodyBuf)
			wc := canonicalizers[bodyCan].CanonicalizeBody(multiWriter)
			
			if _, err := io.Copy(wc, bufr); err != nil {
				return //verif, err
			}

			
			if err := wc.Close(); err != nil {
				return //verif, err
			}
			
			if subtle.ConstantTimeCompare(hasher.Sum(nil), bodyHashed) != 1 {
				return 
			}

			body = canonBodyBuf.Bytes()

		
			// Compute data hash
			hasher.Reset()
			
			picker := newHeaderPicker(h)
			for _, key := range headerKeys {
				kv := picker.Pick(key)
				if kv == "" {
					// The field MAY contain names of header fields that do not exist
					// when signed; nonexistent header fields do not contribute to the
					// signature computation
					continue
				}
				kv = canonicalizers[headerCan].CanonicalizeHeader(kv)

				headerHelper = append(headerHelper, kv...)

				if _, err := hasher.Write([]byte(kv)); err != nil {
					return //verif, err
				}
			}
			canSigField := removeSignature(sigField)
			canSigField = canonicalizers[headerCan].CanonicalizeHeader(canSigField)
			canSigField = strings.TrimRight(canSigField, "\r\n")
			headerHelper = append(headerHelper, canSigField...)
			if _, err := hasher.Write([]byte(canSigField)); err != nil {
				return //verif, err
			}
			hashed := hasher.Sum(nil) 
			headerHash = hashed

			
		}

		headerHelperStr := ByteToString(headerHelper)
		
		

		// Params for signature verify
		jsonHeaderHash := BigIntToArray(64, 4, new(big.Int).SetBytes(headerHash))
		jsonSig := BigIntToArray(64, 32, sigArray)
		jsonKeyN := BigIntToArray(64, 32, googlePubKeyN)
		jsonKeyE := BigIntToArray(64, 32, googlePubKeyE)
		


		jsonObjSig := map[string]interface{}{
			"hashed": BigToString(jsonHeaderHash),
			"sign" : BigToString(jsonSig),
			"exp" : BigToString(jsonKeyE),
			"modulus": BigToString(jsonKeyN),
		}
		jsonBytesSig, err := json.MarshalIndent(jsonObjSig, "", "  ")
		if err != nil {
			t.Log("Error marshaling JSON:", err)
		} else {
			// t.Log(string(jsonBytes))
			err := os.WriteFile("../input-files/signature-input.json", jsonBytesSig, 0644)
			if err != nil {
				t.Log("Error writing JSON to file:", err)
		}
		}



		// Params for gmail-hash-verify
		gmail := contains(headerHelper, []byte("from:")[0])
		highIntHash, lowIntHash := prepareHashInput([]byte(gmail))
		headerHashHigh := new(big.Int).SetBytes(headerHash[0:16])
		headerHashLow := new(big.Int).SetBytes(headerHash[16:32])
		bhHigh := new(big.Int).SetBytes(bodyHashed[0:16])
		bhLow := new(big.Int).SetBytes(bodyHashed[16:32])
		bodyHelperStr := ByteToString(body)

		jsonObj := map[string]interface{}{
			"header": headerHelperStr,
			"gmailHash": []string{
				highIntHash.String(),
				lowIntHash.String(),
			},
			"headerHash": []string{
				headerHashHigh.String(),
				headerHashLow.String(),
			},
			"body": bodyHelperStr,
			"bodyHash": []string{
				bhHigh.String(),
				bhLow.String(),
			},
		}
		jsonBytes, err := json.MarshalIndent(jsonObj, "", "  ")
		if err != nil {
			t.Log("Error marshaling JSON:", err)
		} else {
			// t.Log(string(jsonBytes))
			err := os.WriteFile("../input-files/combined-input.json", jsonBytes, 0644)
			if err != nil {
				t.Log("Error writing JSON to file:", err)
		}
		}

		
		
		

	}

	func bytesToBits(bytes []byte) []int {
		bits := make([]int, 0, len(bytes)*8)
		for _, b := range bytes {
			for i := 7; i >= 0; i-- {
				bit := (b >> i) & 1
				bits = append(bits, int(bit))
			}
		}
		return bits
	}

	func bigIntToBits(n *big.Int) []uint {
		words := n.Bits()
		bits := make([]uint, 0)
		for _, word := range words {
			for i := 0; i < n.BitLen(); i++ {
				bits = append(bits, uint((word>>uint(i))&1))
			}
		}
		return bits
	}

	func contains(slice []byte, item byte) []byte {
		index := -1
		for i, v := range slice {
			if v == item {
				index = i
				break
			}
		}
		fromIndex := -1
		toIndex := -1
		if index != -1 {
			for i := index; i < len(slice); i++ {
				if slice[i] == []byte("<")[0] {
					fromIndex = i+1
					continue
				}
				if slice[i] == []byte(">")[0] {
					toIndex = i
					break
				}
			}
		}
		if fromIndex != -1 && toIndex != -1 {
			gmail := slice[fromIndex:toIndex]
			return gmail
		}
		return []byte{}
	}

	func prepareHashInput(message []byte) (*big.Int, *big.Int) {
		paddedMessage := make([]byte, 32)

		
		
		copy(paddedMessage, message)

		hasher := crypto.SHA256.New()
		hasher.Write(paddedMessage)
		hashBytes := hasher.Sum(nil)
		
		highInt := new(big.Int).SetBytes(hashBytes[0:16])
		lowInt := new(big.Int).SetBytes(hashBytes[16:32])
		return highInt, lowInt
	}

	func BigIntToArray(n int, k int, x *big.Int) []*big.Int {
		mod := new(big.Int).Lsh(big.NewInt(1), uint(n)) // mod = 2^n
		ret := make([]*big.Int, 0, k)
		xTemp := new(big.Int).Set(x)
		for idx := 0; idx < k; idx++ {
			elem := new(big.Int).Mod(xTemp, mod)
			ret = append(ret, elem)
			xTemp.Div(xTemp, mod)
		}
		return ret
	}

	func ByteToString (bytes []byte ) []string {
		bytesString := []string{}
		for _, b := range bytes {
			
			bytesString = append(bytesString,  fmt.Sprintf("%v", b))
		}

		return bytesString
	}

	func BigToString (bigs []*big.Int ) []string {
		bytesString := []string{}
		for _, b := range bigs {
			
			bytesString = append(bytesString,  fmt.Sprintf("%v", b))
		}

		return bytesString
	}