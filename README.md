
# Fuzz Framework
This small framework implementation operates with the Kitty/Katnip fuzzer. It is intended to make a HTTP(s), DNS, Protobuf over HTTP(s) fuzz test easier.


Experimental project.


[![Codacy Badge](https://app.codacy.com/project/badge/Grade/eef3de57d42946c58fc723273a5fe487)](https://www.codacy.com/gh/netlounge/fuzzer_framework/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=netlounge/fuzzer_framework&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.com/netlounge/fuzzer_framework.svg?branch=master)](https://travis-ci.com/netlounge/fuzzer_framework)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/eef3de57d42946c58fc723273a5fe487)](https://www.codacy.com/gh/netlounge/fuzzer_framework/dashboard?utm_source=github.com&utm_medium=referral&utm_content=netlounge/fuzzer_framework&utm_campaign=Badge_Coverage)
---

# Installation

## Check out the repository
Stay on master branch. The tool tested on Python3.6, 3.7.

### Install the following dependencies

#### Deploy Python virtualenv 
If necessary (depends on your environment and needs)
Check whether the package exists and get the version ```python3 -m virtualenv --version``` ``` python3 -m pip install virtualenv```
Create a virtual environment inside the project: ``` python3 -m virtualenv -p python3 .venv```

#### Install PIP dependencies
 Run ```pip install -r requirements.txt``` in the project root after virtualenv has been activated or without it run ```python3 -m pip install -r requirements.txt```.

---
## Set up fuzzer to run tests

The starting point to set up the fuzzer, is the configuration file, which is under the project folder **framework/data/config/framework_config.json** it has four main object type. 

**General fields**:

Key | Value description
-----------| -------------
**verbosity** | set 1 to run on verbose mode;
**target_host** | the host, which is the victim of the fuzz session;
**target_port** | protocol specific port but it can be different according to the implementation of the target listening port;
**tls** | set true if the TLS is a must-have while fuzzing HTTP(s) methods;
**web_port** | is a Kitty specific port where the Kitty web interface is available;
**archive_to_s3** | if true, the framework will archive the results into an S3 bucket;
**protocol** | The next block is about the protocol types, set the appropriate one to true and be careful to set only one protocol to true. 

**Protobuf related fields**:

Key | Value description
-----------| -------------
**proto_path** | is the path where the raw Protobuf files can be found, currently not implemented to compile them;
**pb2_path** | indicates for the system the compiled Protobuf API place;
**modules** | The main Protobuf API component name, which holds all the imported Protobuf packages;
**classes** | The top-level message class name according to the Protobuf API structure, it could be more than one on the top level;
 **enum2class** | The only insufficiency from the Protobuf parser component is that it cannot decide to which ENUM filed belongs to which class, this is the only strict point where the system needs help from the user; The preceding two field which is the module and the classes are only to let the users decide the circle of the module and class to fuzz; These two approaches also a basis for a further development to sophisticate the fuzz session during a Protobuf fuzzing;

**DNS related fields**: 

Key | Value description
-----------| -------------
**tld** | The top-level domain name and the domain to query;
**default_labels** | These domain labels are available represented by a DNS record, and this is the basis of the fuzzed query; 
**timeout** | The time window size what the fuzzer should wait for a DNS response;
**A** | Query A record;
**NS** | Query Name servers;
**TXT** | Query TXT record;

**HTTP related fields**:

Key | Value description
-----------| -------------
**GET** |  to fuzz a HTTP GET method;
**POST_PUT** | POST_PUT is to fuzz a HTTP POST method;
**fuzz_protocol** | set true to fuzz not only the HTTP payload and path (or query string) but the HTTP header fields too;
**content_type** | define the HTTP header content_type;
**path** | REST path or query string;
**sample_payload** | Define the json format of a REST payload or form key-value pairs;
 
With the appropriate configuration file, there is an open way to start a fuzz session. During the session, the framework creates output files tagged with the actual session’s ID. At the end of the session it puts all together into a folder under the framework/bin folder named also to the session’s ID. Under this folder, every report and output log can be found for further inspection if necessary. To debug the system, run it in verbosity mode and read the log files produced by Kitty and the framework. The framework logs every essential step on each stage; it starts and finishes, and logs exceptions where it could be helpful. Each log line contains a timestamp, the component name, the file name, and the line number where the appropriate function step can be found. Whit this logging combined with the Kitty logs and with the session ID, it is an easy process to inspect errors or failures. 

A possible result folder: 
```bash
drwxr-xr-x  21 cvxtct  staff   672B Apr  5 08:33 fea1c9a4-7706-11ea-926c-a45e60d02ac5*
```
And its content:

```bash
*-rw-r--r--   1 cvxtct  staff   1.6K Apr  5 08:33 90-result-dns-fea1c9a4-7706-11ea-926c-a45e60d02ac5.json*
*-rw-r--r--   1 cvxtct  staff   1.9K Apr  5 08:33 91-result-dns-fea1c9a4-7706-11ea-926c-a45e60d02ac5.json*
*-rw-r--r--   1 cvxtct  staff   1.4K Apr  5 08:33 92-result-dns-fea1c9a4-7706-11ea-926c-a45e60d02ac5.json*
*-rw-r--r--   1 cvxtct  staff    43K Apr  5 08:33 fea1c9a4-7706-11ea-926c-a45e60d02ac5-frmwrk_20200405-083051.log*
*-rw-r--r--   1 cvxtct  staff   115K Apr  5 08:33 fea1c9a4-7706-11ea-926c-a45e60d02ac5-kitty_20200405-083051.log*
*-rw-r--r--   1 cvxtct  staff   1.5K Apr  5 08:33 results.xml*
```
* Logfile containing **frmwrk** substring holds the fuzzer framework related application logs. 
* Logfile containing **kitty** substring holds the kitty related application logs. 
* Items with numbes at the beginning are holds error reports from kitty fuzzer.
* ***CI*** systems could grab the ***JUnit*** compatible `result.xml` that provides a report from the tests.


### Prepare and run DNS fuzz tests
Set the configuration generic object:
```json
"generic": {
    "verbosity": 1, 
    "target_host": "localhost",
    "target_port": 53, 
    "tls": false,
    "web_port": 26001,
    "archive_to_s3": false 
  },
```
> **NOTICE** The verbose mode could result files with size that can lead problems.

Set the DNS related objects:
```json
 "dns": {
    "description": "dns related configuration",
    "tld": "foobar.com", 
    "default_labels": "a.b.c.1.2.3.foo.bar",
    "timeout": 5,
    "A": true,
    "NS": false,
    "TXT": false
  },
```
The graph currently uses one template that contains fields and delimiters. It iterates for each label and fuzz them independently after each other, that means if the domain is 123.456.abc.foobar.com:


 123 | . | 456 | . | abc | . | foobar.com
------------ | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- 
field | delimiter |  field | delimiter | field | delimiter | domain 


Delimiter and domain are never under fuzzing. Fields are fuzzing in the order as they appear. 

## Prepare and run HTTP fuzz tests

The fuzzer currently able to fuzz HTTP GET and POST with the given path or query string, or payload it is also capable of fuzz REST APIs. 
Set the configuration generic object (if TLS is a need set it to true and the port to 443):
```json
"generic": {
    "verbosity": 1,
    "target_host": "foo.com",
    "target_port": 8080, 
    "tls": false,
    "web_port": 26001,  
    "archive_to_s3": false 
  },
```
Set the HTTP related objects:
```json
  "http": {
    "description": "http related configuration",
    "GET": true,
    "POST_PUT": false,
    "POST_UPDATE": false,
    "DELETE": false,
    "HEAD": false,
    "fuzz_protocol": false,
    "path": "/foo/bar/bazz",
    "content_type": "text/plain",
    "sample_payload": "{\"data_item\": \"dummy data\"}"
  }
```


## Prepare and run Protocol Buffer fuzz tests over HTTP(s)
Set the compiled protobuf api path in the configuration. It supports the syntax 2.

An example .protoc 
```protobuf

syntax = "proto2";
package test_proto_msg;

import "google/protobuf/timestamp.proto";
import "location.proto";
import "subimport.proto";
import "sub2import.proto";


// [START messages]
message Person {
  required string name = 1;
  required int32 id = 2;  // Unique ID number for this person.
  required string email = 3;

  enum PhoneType {
    MOBILE = 0;
    HOME = 1;
    WORK = 2;
  }

  message PhoneNumber {
    required string number = 1;
    required PhoneType type = 2;
  }

  repeated PhoneNumber phones = 4;

  enum CityType {
    SMALL = 0;
    MID = 1;
    BIG = 2;
  }

  message LocationData {
   required string city_name = 1;
   required int32 pobx = 2;
   required ityType type = 3;
   required test_proto_msg_import.LocationImport LocationImport = 4;
   required test_proto_msg.SubImport SubImport = 5;
   required test_proto_msg.Sub2Import Sub2Import = 6;

   message another {
     required string a = 1;
     required int32 b = 2;

   }

   repeated another an = 8;

  }

  repeated LocationData location = 7;

  required google.protobuf.Timestamp last_updated = 8;
}

// Our address book file is just one of these.
message XxRrrr {
  repeated Person people = 1;
}

// [END messages]
```

The classes_to_send param will pass that particular class to the parser module to produce a Dictionary
that can fuzzed by a Kitty json fuzzer component after some conversion, then the (https://googleapis.dev/python/protobuf/latest/google/protobuf/json_format.html)
json_format Google component populates the given Protobuf message with the fuzzed Dictionary.

**To set up a Protobuff fuzz session with the current component**:
```python
{
  "generic": {
    "verbosity": 1,
    "target_host": "victim-machine-host-name",
    "target_port": 8000,
    "tls": false,
    "web_port": 26001,
    "archive_to_s3": false
  },
  "protocol": {
    "PROTOBUF": true,
    "HTTP": false,
    "DNS": false
  },
  "protobuf": {
    "description": "any description",
    "test_case_desc": "Protobuf test case",
    "proto_path": "/framework/data/proto/",  # not in use;
    "pb2_path": "/framework/models/pb2/api/",  # the compiled pb2 API;
    "modules": ["addressbook"],  # compiled component name, enought the one that implements oders;
    "classes_to_send": ["Person"]  # The subsequent node of the top level message
  }
  ```

##### TYPES, LABELS IN PROTOBUF
```python
        ['TYPE_DOUBLE', 1], 
        ['TYPE_FLOAT', 2], 
        ['TYPE_INT64', 3], 
        ['TYPE_UINT64', 4], 
        ['TYPE_INT32', 5], 
        ['TYPE_FIXED64', 6], 
        ['TYPE_FIXED32', 7], 
        ['TYPE_BOOL', 8], 
        ['TYPE_STRING', 9], 
        ['TYPE_GROUP', 10], 
        ['TYPE_MESSAGE', 11], 
        ['TYPE_BYTES', 12], 
        ['TYPE_UINT32', 13], 
        ['TYPE_ENUM', 14], 
        ['TYPE_SFIXED32', 15], 
        ['TYPE_SFIXED64', 16], 
        ['TYPE_SINT32', 17], 
        ['TYPE_SINT64', 18]

        ['CPPTYPE_INT32', 1], 
        ['CPPTYPE_INT64', 2], 
        ['CPPTYPE_UINT32', 3], 
        ['CPPTYPE_UINT64', 4], 
        ['CPPTYPE_DOUBLE', 5], 
        ['CPPTYPE_FLOAT', 6], 
        ['CPPTYPE_BOOL', 7], 
        ['CPPTYPE_ENUM', 8], 
        ['CPPTYPE_STRING', 9], 
        ['CPPTYPE_MESSAGE', 10]

        ['LABEL_OPTIONAL', 1], 
        ['LABEL_REQUIRED', 2], 
        ['LABEL_REPEATED', 3]
        
```
----


### Archive results into AWS S3
If necesary the S3 archiver component of the framework could be invoke by setting  `"archive_to_s3": true` in *framework_config.json*. This function assumes an active AWS account with aws-cli installed and configured on the machine the fuzzer operates.
***Use this function at your own risk, S3 object upload and storage usage might have costs that depend on several factor!*** 
*AWS S3 pricing*: https://aws.amazon.com/s3/pricing/
 