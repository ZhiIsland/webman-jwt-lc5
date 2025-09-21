#!/usr/bin/env bash
set -e

# Root directory (current dir)
ROOT_DIR="$(pwd)"

# Create directories
mkdir -p .github/workflows
mkdir -p config/plugin/zh/jwt
mkdir -p src/Support
mkdir -p src/Exceptions
mkdir -p src/Contracts
mkdir -p src/Storage
mkdir -p src/Middleware

# Create files (empty placeholders)
touch composer.json
touch .gitignore
touch .gitattributes
touch .github/workflows/ci.yml
touch config/plugin/zh/jwt/app.php

touch src/Support/Config.php

touch src/Exceptions/JwtException.php
touch src/Exceptions/ConfigException.php
touch src/Exceptions/TokenNotProvidedException.php
touch src/Exceptions/TokenInvalidException.php
touch src/Exceptions/TokenExpiredException.php
touch src/Exceptions/TokenBlacklistedException.php
touch src/Exceptions/RefreshTokenAlreadyUsedException.php
touch src/Exceptions/ScopeViolationException.php
touch src/Exceptions/GuardMismatchException.php

touch src/Contracts/JwtStorageInterface.php

touch src/Storage/RedisStorage.php

touch src/KeyManager.php
touch src/JwtManager.php
touch src/TokenExtractor.php

touch src/Middleware/Authenticate.php
touch src/Middleware/Optional.php
touch src/Middleware/RequireScopes.php

touch README.md
touch CHANGELOG.md
touch LICENSE

# Initialize git repository and make initial commit (optional)
if [ ! -d ".git" ]; then
  git init -b main
  git add .
  git commit -m "chore: scaffold project structure for webman-jwt-lc5"
fi

echo "Scaffold created under: ${ROOT_DIR}"
echo "Directories and placeholder files have been created."
echo ""
echo "Next steps (suggested):"
echo "1) Fill files with the implementation and config content."
echo "2) Add remote and push:"
echo "   git remote add origin git@github.com:zhaugielauiita/webman-jwt-lc5.git"
echo "   git push -u origin main"
echo "3) Create tag and push:"
echo "   git tag v0.1.0 -m \"Initial release\""
echo "   git push origin v0.1.0"