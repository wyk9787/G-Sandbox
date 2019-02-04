CXX       	 := clang++
CXXFLAGS 	   := -std=c++11 -fPIC -g
CLIBS        := -ldl -lrt -pthread -lpfm
OBJ_DIR      := ./build
SRC_DIR      := ./src
TEST_DIR     := ./test
TARGET       := ./sandbox
SRC          := $(SRC_DIR)/sandbox.cc 

OBJECTS      := $(SRC:%.cpp=$(OBJ_DIR)/%.o)
TEST_MCF		 := $(TEST_DIR)/mcf/mcf_base.clang $(TEST_DIR)/mcf/train_inp.in	

.PHONY: all test build clean 
	
all: build $(TARGET)

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ -c $<

$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) -shared $(CXXFLAGS) $(CLIBS) -o $(TARGET) $(OBJECTS)

build:
	@mkdir -p $(OBJ_DIR)

clean:
	-@rm -rf $(OBJ_DIR)/*
	-@rm -rf $(TARGET)
	-@rm -rf *.out

