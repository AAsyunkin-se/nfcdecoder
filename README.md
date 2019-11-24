# NfcDecoder

### What is it?

NfcDecoder is a python-based parser of 14443A traffic generated by HydraBus/HydraNFC hardware running under [HydraFW](https://github.com/hydrabus/hydrafw) version 0.9 or later. Sniffs must be in **Text** format, with original whitespace and column style to be retained as saved by the FW (i.e. One Tab between columns). NfcDecoder will produce a CSV file easy to be reformatted later one. Interpretaion scripts are YAML files ('json-ised' in case JSON conversion will be required in the future). YAML is choosen to enable hex numbers and also comments to make it more readable.

### Usage

`python nfcdecoder.py my_sniff.txt`
This will produce `my_sniff.csv` in the same directory as the source sniff.

### Supported Protocols/Targets

* 14443A Target cascaded selection and anticollision with UID retrieval
* 14443A RATS/ATS and 14443-4 Protocol activation (not in full, see TODO list)
* 7816-4 APDU parsing (not in full, see TODO list)
* 14443A Mifare Classic Auth (further traffic encrypted, so no parsing)
* 14443A Mifare Ultralight (not in full, see TODO list)


### Requirements

* Python 3.6.8 or later. (Written and tested on 3.6.8 but may work on earlier 3.6 versions. Will NOT run on 3.5 or any 2.x versions)
* YAML module for Python installed [(PyYaml)](https://pyyaml.org/wiki/PyYAML). If not, simple install is `pip install pyyaml`, or follow [their](https://pyyaml.org/wiki/PyYAMLDocumentation) instructions.
* Default sniff Text format without end frame timestamp or parity. Format is <CPU_Cycles><Tab><Frame_Source><Tab><Frame_Data><LF>
* Good quality sniffs starting from REQA/WUPA. NfcDecoder relies heavily on its internal state machine. It might misinterpret certain data if previous states were skipped for whatever reason.
* CSV editor/viewer. LibreOffice is a better choice than Excel as it will offer initial formatting choices.


### TODO List. Please contribute! (Most important tasks at the top, but any help is very welcome)

If you contribution is about extending the decoder with new protocols, commands etc, then please ensure the source documentation is public access, i.e. not under NDA. Speak to me if in doubt!

* [X] Binary format support in addition to TXT (Beta, Work complete, testing in progress)
* [ ] Help section on how to create your own YAML scripts
* [ ] Complete UL support including Auth and full range of NAKs
* [ ] EMV TLV parsing. There are a number of free TLV parsers (e.g. [BP Tools](https://www.eftlab.com/bp-tools/), [TVR Decoder](https://tvr-decoder.appspot.com/t/home) ) but it will be nice to have something inside NfcDecoder as well, similar to [EMV Framework](https://github.com/apuigsech/emv-framework), but up-to-date and Kernel specific
* [ ] 14443B Protocol support
* [ ] Mifare Desfire and Mifare Plus support
* [ ] NFC Forum Tags

### Bugs

Please submit any issues through NfcDecoder Issues section. It will be very helpful if the sniff file that creates problems is also attached, but make sure it doesn't contain any sensitive information (e.g. live PAN/Track2 data, Cardholder names etc). If it does then use [secret gists](https://gist.github.com/) or mask the sensitive data.
