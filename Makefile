CXX       	 := clang++
CXXFLAGS 	   := -std=c++11 -g -Wall
SRC_DIR      := ./src
MACRO        := DEBUG
TEST_DIR     := ./test
TARGET       := g-sandbox
SRC          := $(SRC_DIR)/sandbox.cc $(SRC_DIR)/ptrace_syscall.cc

OBJECTS      := $(SRC:%.cpp=$(OBJ_DIR)/%.o)

.PHONY: all test clean 
	
all: $(TARGET)

$(OBJ_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ -c $< 

$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -D$(MACRO) `pkg-config --cflags libconfig++` \
		-o $(TARGET) $(OBJECTS) `pkg-config --libs libconfig++`

clean:
	-@rm -rf $(TARGET)
	-@rm -rf *.out

