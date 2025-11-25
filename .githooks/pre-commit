#!/bin/sh
set -e

echo "Ejecuntando pre-commit ..."

echo "Spotless: aplicando formato..."
./gradlew spotlessApply
echo "Actualizando archivos..."
git add -A

echo "Check ..."
./gradlew check

echo "Compilando ..."
./gradlew build

echo "Todo OK. Podes commitear"
exit 0
