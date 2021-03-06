jVault [![Build Status for davidafsilva/jVault](https://img.shields.io/codeship/ecd74dd0-545c-0132-ea32-42ab35009c21/master.svg?style=flat-square)](https://codeship.com/projects/49190) [![Coverage Status for davidafsilva/jVault](http://img.shields.io/coveralls/davidafsilva/jVault/master.svg?style=flat-square)](https://coveralls.io/r/davidafsilva/jVault?branch=master)
=============
jVault is a secure key-value pairs storage.<br/>
The vault ciphers the entries value with AES (variant based on the specified key size) with a key 
derived from a provided password (PBE) and salt. Padding is also added, if required.
Additionally, file based vaults provide integrity check by including a MAC (HMAC with SHA-256) in the file 

Currently, these are the supported vault implementation:

- [In-Memory](https://github.com/davidafsilva/jVault/blob/master/src/main/java/pt/davidafsilva/jvault/vault/InMemoryVault.java)
- [File](https://github.com/davidafsilva/jVault/blob/master/src/main/java/pt/davidafsilva/jvault/vault/ByteFileVault.java)
- [XML](https://github.com/davidafsilva/jVault/blob/master/src/main/java/pt/davidafsilva/jvault/vault/XmlFileVault.java)
- [JSON](https://github.com/davidafsilva/jVault/blob/master/src/main/java/pt/davidafsilva/jvault/vault/JsonFileVault.java)


Usage:
------
#### 1. Use the VaultBuilder to initialize a in-memory secure vault
```java
   final Vault vault = VaultBuilder.create()
                            .inMemory()
                            .password("PM6CduB3rAhcdEKN961NR0583620vHJM")
                            .salt("naoQ8qbq")
                            .iterations(32768)
                            .keySize(256)
                            .build();
```

#### 2. Use the VaultBuilder to initialize a (byte/raw) file based secure vault
```java
   final Vault vault = VaultBuilder.create()
                            .rawFile(FileSystems.getDefault().getPath("vaults", "notes.vault"))
                            .password("PM6CduB3rAhcdEKN961NR0583620vHJM")
                            .salt("naoQ8qbq")
                            .iterations(32768)
                            .keySize(256)
                            .build();
```

#### 3. Use the VaultBuilder to initialize a XML based secure vault
```java
   final Vault vault = VaultBuilder.create()
                            .xmlFile(FileSystems.getDefault().getPath("vaults", "notes.vault"))
                            .password("PM6CduB3rAhcdEKN961NR0583620vHJM")
                            .salt("naoQ8qbq")
                            .iterations(32768)
                            .keySize(256)
                            .build();
```

#### 4. Use the VaultBuilder to initialize a JSON based secure vault
```java
   final Vault vault = VaultBuilder.create()
                            .jsonFile(FileSystems.getDefault().getPath("vaults", "notes.vault"))
                            .password("PM6CduB3rAhcdEKN961NR0583620vHJM")
                            .salt("naoQ8qbq")
                            .iterations(32768)
                            .keySize(256)
                            .build();
```

Key sizes:
------
Beware of the out-of-the-box restrictions that Java has regarding key sizes, the jurisdiction policy files shipped with the Java SE Development Kit allow "strong" but limited cryptography to be used.
For more information please visit the [JCA Docs](http://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#importlimits).

Logging:
------
Beware of logging in the current release, debug logging might expose sensitive data. As such, 
debug level should only be used for it's purpose, debugging, development.

Copyright &copy;
---------
    Copyright (C) 2014 David Silva
 
    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:
    
    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
    
    3. Neither the name of the David Silva nor the names of its contributors
       may be used to endorse or promote products derived from this software without
       specific prior written permission.
    
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
    INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
    OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
    OF THE POSSIBILITY OF SUCH DAMAGE.
