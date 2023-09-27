#!/bin/bash

mvn -B release:prepare
mvn -B release:perform
