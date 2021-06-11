Digital Green Certificates (DGC)
================================

This repo aims as a starting point for DGC (aka vaccination certificates)
forensics. It collects standards, documents and other resources
which are necessary to understand DGCs and the crypto behind it.

If you [wonder about the name](https://www.youtube.com/watch?v=NUTGr5t3MoY) of this repo.

The documents are under the Creative Commons CC 3.0 (WHO) and 4.0 (EU)
license, as stated within the particular PDF files. None of the documents
were modified and are just a pure copy in order to have them in a single place. There are some EU documents which explicitly have a more strict
licensing and are theoretically only distributable by EU or
their member states. Though, they may be downloaded
[here (EU DPIA-Draft)](https://ec.europa.eu/health/sites/default/files/ehealth/docs/efgs_dpia_en.pdf) and are therefore not part of this repo.


Additional resources:

* [MohGovIL Ramzor](https://github.com/MohGovIL/Ramzor)

* [EU DGC github](https://github.com/eu-digital-green-certificates)

* [EU eHN devel coordination](https://github.com/ehn-digital-green-development)

* [EU ehealth docs](https://ec.europa.eu/health/ehealth/key_documents_en)

* [DGC of the State of Berlin](https://gitlab.com/ponci-berlin)

* [CovPass (DGC Germany)](https://github.com/digitaler-impfnachweis)


Security
--------

This section contains abitrary research results. There are some general problematic
key points which I won't outline here, but if it gets specific such as failures in
verification apps etc, I will add it here.

After reading the CWA section you will get an idea where the problems about the
crypto will be originated from in future.


Corona Warn App (CWA)
---------------------

*c-skills* reviewed the source of the german *Corona Warn App* that may
store vaccination certificates (Version 2.3.2 as released yesterday 10/06/2021)
and found that the verification part of the COSE cryptographic signatures is just missing.
Rather, the kotlin code just parses the COSE data as normal CBOR:

```java
package de.rki.coronawarnapp.vaccination.core.qrcode

import de.rki.coronawarnapp.bugreporting.censors.vaccination.CertificateQrCodeCensor
import de.rki.coronawarnapp.coronatest.qrcode.QrCodeExtractor
import de.rki.coronawarnapp.util.compression.inflate
import de.rki.coronawarnapp.util.encoding.Base45Decoder
import de.rki.coronawarnapp.vaccination.core.certificate.HealthCertificateCOSEDecoder
import de.rki.coronawarnapp.vaccination.core.certificate.HealthCertificateHeaderParser
import de.rki.coronawarnapp.vaccination.core.certificate.InvalidHealthCertificateException
import de.rki.coronawarnapp.vaccination.core.certificate.InvalidHealthCertificateException.ErrorCode.HC_BASE45_DECODING_FAILED
import de.rki.coronawarnapp.vaccination.core.certificate.InvalidHealthCertificateException.ErrorCode.HC_ZLIB_DECOMPRESSION_FAILED
import de.rki.coronawarnapp.vaccination.core.certificate.RawCOSEObject
import de.rki.coronawarnapp.vaccination.core.certificate.VaccinationDGCV1Parser
import timber.log.Timber
import javax.inject.Inject

class VaccinationQRCodeExtractor @Inject constructor(
    private val coseDecoder: HealthCertificateCOSEDecoder,
    private val headerParser: HealthCertificateHeaderParser,
    private val bodyParser: VaccinationDGCV1Parser,
) : QrCodeExtractor<VaccinationCertificateQRCode> {

    override fun canHandle(rawString: String): Boolean = rawString.startsWith(PREFIX)

    override fun extract(rawString: String): VaccinationCertificateQRCode {
        CertificateQrCodeCensor.addQRCodeStringToCensor(rawString)

        val parsedData = rawString
            .removePrefix(PREFIX)
            .decodeBase45()
            .decompress()
            .parse()

        return VaccinationCertificateQRCode(
            parsedData = parsedData,
            qrCodeString = rawString,
        )
    }

    private fun String.decodeBase45(): ByteArray = try {
        Base45Decoder.decode(this)
    } catch (e: Throwable) {
        Timber.e(e)
        throw InvalidHealthCertificateException(HC_BASE45_DECODING_FAILED)
    }

    private fun ByteArray.decompress(): RawCOSEObject = try {
        this.inflate(sizeLimit = DEFAULT_SIZE_LIMIT)
    } catch (e: Throwable) {
        Timber.e(e)
        throw InvalidHealthCertificateException(HC_ZLIB_DECOMPRESSION_FAILED)
    }

    fun RawCOSEObject.parse(): VaccinationCertificateData {
        Timber.v("Parsing COSE for vaccination certificate.")
        val cbor = coseDecoder.decode(this)

        return VaccinationCertificateData(
            header = headerParser.parse(cbor),
            certificate = bodyParser.parse(cbor)
        ).also {
            CertificateQrCodeCensor.addCertificateToCensor(it)
        }.also {
            Timber.v("Parsed vaccination certificate for %s", it.certificate.nameData.familyNameStandardized)
        }
    }

    companion object {
        private const val PREFIX = "HC1:"

        // Zip bomb
        private const val DEFAULT_SIZE_LIMIT = 1024L * 1024 * 10L // 10 MB
    }
}

```

The CWA is **not** the *CovPass* verification app but it was announced to the public
as one of the official verification methods yesterday along with *CovPass*.

As the crypto part is just missing, you can upload arbitrary JSON data to the CWA,
given that it satisfies the EU specification of the JSON schemas which are in this repo under *specs*
and make CWA find the necessary JSON tags.

The JSON I used is:

```json
{ "ver": "1.2.1", "nam": { "fn": "RAMBO", "gn": "John", "fnt": "RAMBO", "gnt": "John" }, "dob": "1990-11-11", "v":[{"tg": "840539006", "vp": "1119349007", "mp": "EU/1/20/1528", "ma": "ORG-7350", "dn": 2, "sd": 2, "dt" : "2021-04-21", "co": "DE", "is": "c-skills","ci": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ" }]}
```

At least its asking for trouble to let users upload unsigned certificates into the official corona app
and placing a check-mark behind it, if your threat models are fake DGCs. And this threat model is what the
entire topic is about.
My assumption is that the cryptographic verification is/was planned to happen, but there was no time setting
up the backend PKI to distribute the keys before app release. If you read the specifications, you will find that
there are quite some standards to fulfil for all EU countries until everything is working.

In practise, the fake DGC looks like this:


<p align="center">
<img src="https://github.com/stealth/greenday/blob/master/rambo.jpg" />
</p>


Even if all other DGC verification apps are secure (a theory left to prove),
you have to consider that someone possibly tampered with the QR code before importing or the signature
is simply broken when you obtained it from the doctor. In that case you may travel with an invalid
DGC, putting trust into the blue check-mark and are then stopped at the border in nowhere-land.

German specifics
----------------

If almost every doctor and med-shop is in possession of creating DGCs for citizens, the day will
come when private signing keys leak or quite a large batch of DGCs is falsely signed or malware
is submitting false DGCs for signing to a central authority if a central approach is used.
If I didn't miss anything (please correct me if I am wrong), the HC1 certificates do not contain a JSON
tag for the *date of signing* (and possibly location or ID of signing entity). This makes it impossible to revoke
invalid DGCs without a lot of hazzle and invoking quite a lot valid DGCs along with it (maybe even all
valid DGCs until the day of revocation). This would make the entire DGC approach useless.


Privacy
-------

The person of which the DGC is checked at shop-entry, bar, club or travel has no way to make sure the
verifier is not using a patched app to store and possibly sell all information it gets out of the QR code.
As a bonus, the id-card's name is matched with that data. Just imagine the power of border control capabilities
in the hand of underpayed security guards at concert halls. Checking passports, id-cards (and now DGCs) is a task
that should only be executed by gov authorities, in particular if the data is made of bits.

