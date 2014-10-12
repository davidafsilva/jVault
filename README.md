jVault
=============
jVault is a secure key-value pairs storage.<br/>
The vault ciphers the entries value with AES (variant based on the specified key size) with a key derived from a provided password (PBE) and salt. Padding is also added, if required.

Currently, there's only one vault implementation supported: [In-Memory](https://github.com/davidafsilva/jVault/blob/master/src/main/java/pt/davidafsilva/jvault/InMemoryVault.java).


Usage:
------
#### 1. Use the VaultBuilder to initialize a secure vault
```java
   final Vault vault = VaultBuilder.create()
                            .password("PM6CduB3rAhcdEKN961NR0583620vHJM")
                            .salt("naoQ8qbq")
                            .iterations(32768)
                            .keySize(256)
                            .build();
```


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
