# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Define your project name
project(JJSpoof_Project LANGUAGES CXX)

# Set the C++ standard to C++11 or higher (FLTK often benefits from this)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add your custom include directory
# This tells CMake where to find the FLTK header files (e.g., Fl.H)
include_directories(./include)

# Add your custom library directory
# This tells CMake where to find the FLTK static libraries
link_directories(./lib)

# Define your executable
# This creates an executable target named 'JJ-Spoof' from your source file
add_executable(JJ-Spoof JJ-Spoof.cpp)

# Link the FLTK libraries to your executable
# You need to link all the FLTK libraries your program uses.
# Based on your 'lib' directory, you'll likely need at least fltk, fltk_images, etc.
# The order sometimes matters, especially for dependencies (e.g., fltk_images might depend on fltk_jpeg and fltk_png).
target_link_libraries(JJ-Spoof
    fltk
    X11
    Xext
    Xft
    fontconfig
    Xinerama
    Xcursor
    Xfixes
    Xrender
    stdc++
    pthread
    dl
)

# Optional: Add compiler flags if needed (e.g., for release builds)
# You can uncomment and modify these as necessary
# target_compile_options(JJ-Spoof PRIVATE -O3 -DNDEBUG)

# Optional: Install the executable
# install(TARGETS JJ-Spoof DESTINATION bin)