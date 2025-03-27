# ProArt ASCII Generator

## Description

ProArt ASCII Generator is a Python-based application built with Tkinter that allows users to convert images into ASCII art. Users can customize the ASCII art by adjusting settings such as the width, style, and color theme. The application also supports saving the generated ASCII art to a text file and copying it to the clipboard.

## Features

- **Image to ASCII Conversion**: Convert any image to ASCII art with various styles and color themes.
- **Theme Support**: Choose between dark and light themes for the user interface.
- **Customizable Settings**: Adjust the width of the ASCII art and select from three ASCII character styles.
- **Preview Panel**: View the image and generated ASCII art side by side.
- **Save & Copy**: Save the generated ASCII art to a file or copy it to the clipboard.
- **Progress Bar**: See the progress of the ASCII generation process.

## Requirements

- Python 3.x
- Tkinter (comes pre-installed with Python)
- Pillow (`PIL`) for image processing

To install Pillow, use the following command:

```bash
pip install pillow
```

## Installation

1. Clone this repository or download the Python script.
2. Install the required dependencies (Tkinter and Pillow).
3. Run the script:

```bash
python ascii_generator.py
```

## Usage

1. **Open Image**: Click the "Open Image" button to load an image from your computer.
2. **Set Width**: Adjust the width of the ASCII art by using the slider.
3. **Select Style**: Choose an ASCII character style from the dropdown (Dense, Medium, Light).
4. **Select Color**: Pick a color theme for the ASCII art (Hacker Green, Cyber Red, Ocean Blue, Classic White).
5. **Generate**: Click the "Generate" button to convert the image to ASCII art.
6. **Preview**: The ASCII art will appear in the preview panel.
7. **Save**: Save the generated ASCII art to a file.
8. **Copy**: Copy the generated ASCII art to the clipboard.

## Screenshots

![Screenshot 1](screenshot1.png)
*Image preview panel with ASCII art and image preview.*

![Screenshot 2](screenshot2.png)
*Control and settings panel.*

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
