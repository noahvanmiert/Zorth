# Zorth

**Zorth** is a stack-based programming language inspired by [Porth](https://gitlab.com/tsoding/porth), created by Tsoding. Zorth emphasizes simplicity and minimalism while providing a robust set of features for modern programming tasks. This README provides an overview of Zorth, including its features, usage, and development information.

**IMPORTANT**: Please note that Zorth is still in its early stages of development and currently has limited features.


## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Credits](#credits)
- [License](#license)


## Introduction


Zorth is designed to be a minimalist and easy-to-use stack-based language. Inspired by [Porth](https://gitlab.com/tsoding/porth).


## Features


- **Stack-Based Execution**: Utilizes a stack-based architecture for managing data and operations.
- **Minimalist Syntax**: Offers a clean and simple syntax aimed at reducing complexity.
- **Flexible Design**: Designed to be extensible and adaptable for various programming tasks.


## Installation

To get started with Zorth, follow these steps:

1. **Clone the repository:**

    ```sh
    git clone https://github.com/noahvanmiert/Zorth.git 
    ```

2. **Build the compiler:**
    
    ```sh
    cd Zorth
    zig build 
    ```

    You will find the executable in the zig-out/bin folder.


## Usage


Here is a basic guide to using Zorth:

1. **Write a program:**
    
    ```
    include "std/std.zorth"

    "Hello, World!\n" puts
    ```

2. **Compile the program:**

    ```sh
    zorth example.zorth
    ```

3. **Run the compiled program:**
    
    ```sh
    ./output
    ```


## Examples


Here are a few example programs in Zorth:

1. **Hello, World**:

    ```
    include "std/std.zorth"

    "Hello, World!\n" puts
    ```

2. **Basic Arithmetic**:
    
    ```
    5 3 + dump
    ```


## Credits


Zorth is heavily inspired by [Porth](https://gitlab.com/tsoding/porth), a stack-based language created by Tsoding. 


## License


Zorth is licensed under the [MIT License](https://en.wikipedia.org/wiki/MIT_License). See the `LICENSE` file for more details.
