# Burp Extension Development Series 

This repo is a series of handouts which will focus on the development of Burp Suite extensions using [IntelliJ](https://www.jetbrains.com/idea/) & [Java Interfaces](http://tutorials.jenkov.com/java/interfaces.html). When I first started to create extensions for  Burp Suite it was a pain to figure out where to start from or even to find straight-forward sequential resources online was difficult.

Burp Suite plugin development is pretty simple, just that there are not much resources online which points in development of such plugins from scratch.

The code presented in the series has been tested with:  
|Tool|Version|
|-|-|
|`java`|`11.0.6`|
|`Burp`|`CE v2.1.02`|
|`IntelliJ`|`UE v2019.3.4`|

## Prerequisite
- Working with Java and IntelliJ to some extent.
- Understanding of
    - [Java Basics](https://www.tutorialspoint.com/java/index.htm)
    - [Java Interfaces](https://www.jetbrains.com/idea/)
- Burp :grin:

## Table of Content
1. [What is Burp Extender?](series/Chapter1/README.md)
    1. [What is Burp Extender?](series/Chapter1/README.md#Burp-Extender)
    2. [What are Burp API Extender interfaces?](series/Chapter1/README.md#Burp-Extender-Interfaces)
    3. [Setup Dev Environment using IntelliJ](series/Chapter1/README.md#setup-dev-environment-using-IntelliJ) 
    4. [Code](code/BurpExtenderChapter1)
2. [Creating a Hello World Extender](series/Chapter2/README.md)
    1. [Setting up Extender Development Environment](series/Chapter2/README.md#setting-up-extender-development-environment)
    2. [Hello Burp](series/Chapter2/README.md#hello-burp)
    3. [Understanding Hello Burp](series/Chapter2/README.md#understanding-hello-burp)
    4. [Code](code/BurpExtenderChapter2)
3. [Deep Dive into Extender API Interface](series/Chapter3/README.md)  
    1. [Helper Interface](series/Chapter3/README.md#helper-interface)
    1. [Simple URL Encoder](series/Chapter3/README.md#simple-url-encoder)
    2. [Interface Registration](series/Chapter3/README.md#interface-registration)
    3. [Listen for events from Proxy](series/Chapter3/README.md#listen-for-events-from-proxy)
    3. [Code](code/BurpExtenderChapter3)
4. [Understanding a use case: Intruder Payload processing](series/Chapter4/README.md)
    1. [Code](code/BurpSuiteExtenderChapter4)
5. [Burp Suite Extension - Event Listeners](series/Chapter5/README.md)
    1. [Code](code/BurpExtenderChapter5)
6. [Burp Suite Extension - Session Tokens Modification]()
5. [Burp Suite Extension - Create HTTP Proxy plugin Example : JWT token on the Go]()
6. [Burp Suite Extension - Create a Separate tab plugin : JWT Encode/Decode]()
5. [Next steps]()

This series is targeted for those, who are interested in **Security Research**, **Bug Hunting**, **Security Engineers** etc. The main requirement is to get the best out of this series is that reader should be able to understand the code written in `Java`. 

> Burp Offers to write the extensions in Java, Jython, And JRuby. Easiest of all is to prefer writing such extensions in Java. Even I prefer to write it in Java, over the other alternatives because of community support for Java and related tools compared to Jython or JRuby. Writing the same solutions in Jython or JRuby wont be tricky, the extension interfaces exposes similar functionalities, rather it would just requirer the environment (Dev & Runtime) to support those.

This is intentionally not targeted as blog post, rather this have been intentionally kept over GitHub to attract support from Community, from the professionals working in similar domain and from their expertise.
