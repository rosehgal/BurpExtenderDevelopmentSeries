# Burp Extension Development Series 

This repo is a series of handouts which will focus on the development of Burp Suite extensions using [IntelliJ](https://www.jetbrains.com/idea/) & [Java Interfaces](http://tutorials.jenkov.com/java/interfaces.html). When I first started to create extensions for  Burp Suite it was a pain to figure out where to start from or even to find straight-forward sequential resources online was difficult.

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
    1. [Setting up Extender Development Environment](#setting-up-extender-development-environment)
    2. [Hello Burp](#hello-burp)
    3. [Understanding Hello Burp](#understanding-hello-burp)
    4. [Code](code/BurpExtenderChapter2)
3. [Deep Dive into Extender API Interface]()  
    1. [Helper Interface](#helper-interface)
    1. [Simple URL Encoder](#simple-url-encoder)
    2. [Interface Registration](#interface-registration)
4. [Understanding a use case: Intruder Payload processing]()
5. [Burp Suite Extension - Event Listeners]()
6. [Burp Suite Extension - Session Tokens Modification]()
5. [Burp Suite Extension - Create HTTP Proxy plugin Example : JWT token on the Go]()
6. [Burp Suite Extension - Create a Separate tab plugin : JWT Encode/Decode]()
5. [Next steps]()

This series is targeted for those, who are interested in **Security Research**, **Bug Hunting**, **Security Engineers** etc. The main requirement is to get the best out of this series is that reader should be able to understand the code written in `Java`. 

> Burp Offers to write the extensions in Java, Jython, And JRuby. Easiest of all is to prefer writing such extensions in Java. Even I prefer to write it in Java, over the other alternatives because of community support for Java and related tools compared to Jython or JRuby. Writing the same solutions in Jython or JRuby wont be tricky, the extension interfaces exposes similar functionalities, rather it would just requirer the environment (Dev & Runtime) to support those.

This is a not targeted as blog post, rather this have been intentionally kept over GitHub to attract support from Community, from the professionals working in similar domain and from their expertise.