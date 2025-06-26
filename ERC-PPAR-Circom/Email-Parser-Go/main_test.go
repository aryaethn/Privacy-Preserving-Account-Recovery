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
package dkim

	import (
		"crypto"
		"crypto/rsa"
		"math/big"
		"fmt"
		"strings"
		"testing"

		"crypto/subtle"
		

		"bufio"
		"io"
		
	)
	
	
	
	// --- Test Data Setup ---
	var (
		Email = `Received: from 127.0.0.1
 by atlas-production.v2-mail-prod1-gq1.omega.yahoo.com pod-id atlas--production-gq1-655cc88fc4-nczw5.gq1.yahoo.com with HTTP; Fri, 6 Jun 2025 16:43:48 +0000
Return-Path: <arianari97@gmail.com>
X-Originating-Ip: [209.85.128.175]
Received-SPF: pass (domain of gmail.com designates 209.85.128.175 as permitted sender)
Authentication-Results: atlas-production.v2-mail-prod1-gq1.omega.yahoo.com;
 dkim=pass header.i=@gmail.com header.s=20230601 arc_overridden_status=NOT_OVERRIDDEN;
 spf=pass smtp.mailfrom=gmail.com arc_overridden_status=NOT_OVERRIDDEN;
 dmarc=pass(p=NONE,sp=QUARANTINE) header.from=gmail.com arc_overridden_status=NOT_OVERRIDDEN;
X-Apparently-To: akn97@yahoo.com; Fri, 6 Jun 2025 16:43:49 +0000
X-YMailISG: lDjUN34WLDtbSe9T1lApbJhiN_9YNXuwT3dSvnDcHDu3FIH.
 n8fYkaKaIiLNUugKWuZO9hJww5IkgpOPmg7gHvE.4xYiWvDzlE4Hpotz39xN
 whvUFHgD0ireYGEr2e64WzwCPfg4e7DZ9cRho1EXGjoc1xpGqAA7TFvI.Ite
 gZCpEAiauDxvHCA_1nYw_EFgrSDI_psnbk4pgSwUS92FVdIdiNc3aws1.drq
 st4Ue2VZ2AlSzeZNlTr4rU238x033G9px75XmRiPeo4QcbJyc98tQQ3JoZg.
 f4w8bZ_K6GFUc.2ezGa0zLtg5YpU2OWCyEyJfU4brtBzlGz.rfBEtx5PRWpt
 t3EOBqItQ2.VE1_rh0qKoPXZlg7MTum3xhbYDvtcdkoKypWTbP4wYZaLXdA9
 PgfyLhMXrFmzygcV9S0YNNLekJ6_tUYE70Ep.akqOh_Pl1QGw_VSrory4HIR
 mCdqtHBd9vmuW7Dp45VzBonhFBGNQ9fYInQcwkXNkzxQbtE9ZSIY96GESMoK
 dqFCBRQUr3ruE5OhBeibhxSSK1kLW1P28ofUj7eHrMO9508o2Myma6M1zX_b
 3cgLnOIIVz1GxZGEdvzEvq0lII_cm8TTdWcW2dFwnoliLwFyGpWucHGiMpJs
 HrQJI1xEvYeCzHv1WCsh912ApJkLq6U8HXwxZoeTKe7A2OeYRD3KdD_pZIrq
 1DTpVkeSwueEi6Znjg0uf6aQgdokEafg_XL_O7QNhWWd3S.dTH.zJIUQ7JxO
 VwSzkALLaMH8BwMYFslta7QLotvA8kjYZ54LCViU4PJ97caP3YATN_J5q6nF
 xSaQBdZ2Y6ua4ENfestRTYV1OQvY03RGQCSdLiKNLsze3iO51x_95ehekrCd
 QvM1kqmg_rNI0CZBShQTblFQRKRrvnvJASQQS8fG5NlMVsAGjLBKDig4G1wy
 wREMnFCYPdu8XUHxvBHw_PG8eIcwA5JbUsQLRWLx4z3_YJQH.vyNpObOLbt6
 D2A3c35kwHtPLQAPvO5OtG3pPqkTJ2bMYD_QJtBfy42YjseidJVEGA8Eer74
 6Lf.EA8m_n8cEi4HYlNHgAY-
Received: from 209.85.128.175 (EHLO mail-yw1-f175.google.com)
 by 10.253.62.170 with SMTPs
 (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256);
 Fri, 06 Jun 2025 16:43:48 +0000
Received: by mail-yw1-f175.google.com with SMTP id 00721157ae682-70e4043c5b7so20982667b3.1
        for <akn97@yahoo.com>; Fri, 06 Jun 2025 09:43:48 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1749228228; x=1749833028; darn=yahoo.com;
        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject
         :date:message-id:reply-to;
        bh=uSp5y7DseScBF1AhvkUDmnZAN/jLZJbpA2qzrujwLRU=;
        b=i8RewlL94oq6f5+ybaZuZOFA0LVH/nj6xpbAisJc8p+KPqsCh01iPz8Ba9vge4Lkf7
         E6vTJ0izSfTx5ZJZy3Q18KiQ2zLMB0bm9WlLVpknT59CqzDkp5sdA8oFuPNXOrNhoD/p
         CpmjkeGhy6Rb0NMz6Lx4uDDuY0rMTCz2+cvaN2G+kjZVhQ9R2wFxub3IwdRrj535qB82
         B07FCeQ6VdNXUQ8jYljHUzYN8jRnKX9YhwKsDo/L1eXgK+Z4vgGRL+7BlpsVj6UCe/ve
         lD1CPSDNyBQicEyWBnI6NjjVlO2Jl6R5s3Wu5FAVAeAd1ywDCBmq6551e/HE2e9U0fFg
         2mtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749228228; x=1749833028;
        h=to:subject:message-id:date:from:mime-version:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uSp5y7DseScBF1AhvkUDmnZAN/jLZJbpA2qzrujwLRU=;
        b=H2N3MVNTdsZum+HkINMsr/sjGUiV80ISMgFjLElNSORus60NhETPa1ji1NXyYqfRWl
         /lhrTCyJp7x5PkGupw8BqklZn0/GRwiQe+B9rw8V1eEtw4twQvhurLMvBQVkwcH8LJYT
         FkPAwyU3KZRMrhpZl8MxxsZX1UcKeHh2EnpfJqru+jTtpJXqYP6yyucsSIWc3oJt5LIO
         mlj8kHXJD6ZaU/KC28T6jz6d6Z59GtrxM/j14wHZD+Z2Yg2l0w5MKu5B6J3XEHWHmg7W
         QVhQ2NdkeivoUO5CzFU9yWpX5FFMxmLlJ1u0tOlgg/3mAeIXEdaFQelcoyPm66orRTeD
         MX3w==
X-Gm-Message-State: AOJu0YxMjpX0mCb0lDjeuhJb4r2g11zsTrEKzkeZRZdxSxkSwTjMLkck
	DOZ2CcabsQ6j9Y1uIee6mRxnva3sxp7QkiuH/tOJb5dQhnSlgFlJWFmMh5E1xWdUBJJZpa/I5It
	F3OaY2iCdvdGyEpDZFBBzdg6ca1jEFa9NR0t118mPNXJG
X-Gm-Gg: ASbGnctYY+WVUuwPYUhJdwx7t/7VV2CqNHGTrdsxbv90BqPQinkj4IdZK3tb+FA5ibG
	YqUmgE7IykDm+A/5fmJ3gd+B2OAkR4N/e8gPGe/lsxiJtz2xbgMRMSBsWnAVQv1xSeP9U/+QlKP
	cUisCQmSUIHPfaCRfi1egKkfz0O+25DmT1
X-Google-Smtp-Source: AGHT+IF0KM/2aaDCsJwTT/wNSkXKm0LELyU5XGrYJVk1nCfNR74ephXXM9VltTffqC+KiNtaIsWG2rzRujHDhEhyQV4=
X-Received: by 2002:a05:690c:74c1:b0:710:f1da:1b5f with SMTP id
 00721157ae682-710f7736183mr59496387b3.34.1749228228261; Fri, 06 Jun 2025
 09:43:48 -0700 (PDT)
MIME-Version: 1.0
From: Aria Naraghi <arianari97@gmail.com>
Date: Fri, 6 Jun 2025 19:43:36 +0300
X-Gm-Features: AX0GCFsxi2w1JeZ6eU77AxP028W2pH3Tk5x1p9mRbdZD7AfXKqWaDLP-eV7yeRk
Message-ID: <CAAuWrvVvkvjk8-MFy15duX14jYN6S69nrX2Un36RuEb1hCitOw@mail.gmail.com>
Subject: test
To: Aria Nari <akn97@yahoo.com>
Content-Type: multipart/alternative; boundary="0000000000002d3b620636e9ef8e"
Content-Length: 217

--0000000000002d3b620636e9ef8e
Content-Type: text/plain; charset="UTF-8"

123456

--0000000000002d3b620636e9ef8e
Content-Type: text/html; charset="UTF-8"

<div dir="ltr">123456</div>

--0000000000002d3b620636e9ef8e--
`
	)
	
	func TestEmailSignatureVerification(t *testing.T) {
		bh := new(big.Int)
		sigArray := new(big.Int)
		header := new(big.Int)
		headerHash := []byte{}
		googlePubKeyN := new(big.Int)
		googlePubKeyE := 0
		headerHelper := []byte{}

		t.Log("[Signature] Starting test...")

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
			// TODO: compute hash in parallel
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
			googlePubKeyE = verif.E
			if err != nil {
				return //verif, err
			} else if res == nil {
				return //verif, permFailError("unsupported public key query method")
			}

		
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
			bodyHashed, err := decodeBase64String(params["bh"])
			bh = big.NewInt(0).SetBytes(bodyHashed)
			if err != nil {
				return //verif, permFailError("malformed body hash: " + err.Error())
			}
			sig, err := decodeBase64String(params["b"])
			sigArray = big.NewInt(0).SetBytes(sig)
			if err != nil {
				return //verif, permFailError("malformed signature: " + err.Error())
			}
			// Check body hash
			hasher := hash.New()
			wc := canonicalizers[bodyCan].CanonicalizeBody(hasher)
			if _, err := io.Copy(wc, bufr); err != nil {
				return //verif, err
			}
			if err := wc.Close(); err != nil {
				return //verif, err
			}
			if subtle.ConstantTimeCompare(hasher.Sum(nil), bodyHashed) != 1 {
				return //verif, failError("body hash did not verify")
			}
		
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
			header = big.NewInt(0).SetBytes(headerHelper)
			if _, err := hasher.Write([]byte(canSigField)); err != nil {
				return //verif, err
			}
			hashed := hasher.Sum(nil) 
			headerHash = hashed

			
		}

		headerHelperStr := "["
		for i, b := range headerHelper {
			if i > 0 {
				headerHelperStr += ","
			}
			headerHelperStr += "\"" + fmt.Sprintf("%v", b) + "\""
		}
		headerHelperStr += "]"

		// Params for signature verify
		fmt.Println("header:  (bytes)  ", header)
		//fmt.Println("bh:  (big int)  ", bh)
		fmt.Println("sigArray:  (big int)  ", sigArray)
		fmt.Println("googlePubKeyN:  (big int)  ", googlePubKeyN)
		fmt.Println("googlePubKeyE:  (int)  ", googlePubKeyE)

		// Params for gmail-hash-verify
		fmt.Println("header:  (bytes)  ", header)
		gmail := contains(headerHelper, []byte("from:")[0])
		highIntHash, lowIntHash := prepareHashInput([]byte(gmail))
		fmt.Println("highIntHash:  (big int)  ", highIntHash)
		fmt.Println("lowIntHash:  (big int)  ", lowIntHash)
		//fmt.Println("header:  (big int)  ", headerHelper)

		// Params for header-hash-verify
		fmt.Println("header:  (bytes)  ", header)
		fmt.Println("headerHash:  (big int)  ", headerHash)	
		headerHashHigh := new(big.Int).SetBytes(headerHash[0:16])
		headerHashLow := new(big.Int).SetBytes(headerHash[16:32])
		fmt.Println("headerHashHigh:  (big int)  ", headerHashHigh)
		fmt.Println("headerHashLow:  (big int)  ", headerHashLow)

		// Params for body-hash-verify
		// <--TODO-->

		// fmt.Println("headerHelper Size:  (int)  ", len(headerHelper))
		// fmt.Println("headerHelper (formatted):", headerHelperStr)
		

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