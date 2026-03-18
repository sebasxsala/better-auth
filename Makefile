# Better Auth Ruby - Workspace Makefile
# Comandos para trabajar con todos los packages del monorepo

BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
NC := \033[0m

# =============================================
# INSTALACIÓN
# =============================================

.PHONY: install
install:
	@echo "$(BLUE)📦 Instalando dependencias del workspace...$(NC)"
	bundle install
	@echo "$(BLUE)📦 Instalando better_auth...$(NC)"
	cd packages/better_auth && bundle install
	@echo "$(BLUE)📦 Instalando better_auth-rails...$(NC)"
	cd packages/better_auth-rails && bundle install
	@echo "$(GREEN)✓ Todas las dependencias instaladas$(NC)"

.PHONY: setup
setup: install
	@echo "$(GREEN)✓ Workspace configurado$(NC)"

# =============================================
# DESARROLLO
# =============================================

.PHONY: console
console:
	@echo "$(BLUE)💻 Abriendo consola del workspace...$(NC)"
	bundle exec irb -r bundler/setup -r better_auth -r better_auth/rails

# =============================================
# LINTING
# =============================================

.PHONY: lint
lint:
	@echo "$(BLUE)🔍 Revisando estilo del workspace...$(NC)"
	bundle exec standardrb
	@echo "$(BLUE)🔍 Revisando better_auth...$(NC)"
	cd packages/better_auth && bundle exec standardrb
	@echo "$(BLUE)🔍 Revisando better_auth-rails...$(NC)"
	cd packages/better_auth-rails && bundle exec standardrb
	@echo "$(GREEN)✓ Linting completado$(NC)"

.PHONY: lint-fix
lint-fix:
	@echo "$(BLUE)🔧 Corrigiendo estilo automáticamente...$(NC)"
	bundle exec standardrb --fix
	cd packages/better_auth && bundle exec standardrb --fix
	cd packages/better_auth-rails && bundle exec standardrb --fix
	@echo "$(GREEN)✓ Código corregido$(NC)"

# =============================================
# TESTING
# =============================================

.PHONY: test
test:
	@echo "$(BLUE)🧪 Ejecutando tests del workspace...$(NC)"
	bundle exec rake ci

.PHONY: test-core
test-core:
	@echo "$(BLUE)🧪 Ejecutando tests de better_auth...$(NC)"
	cd packages/better_auth && bundle exec rake test

.PHONY: test-rails
test-rails:
	@echo "$(BLUE)🧪 Ejecutando tests de better_auth-rails...$(NC)"
	cd packages/better_auth-rails && bundle exec rspec

.PHONY: ci
ci:
	@echo "$(BLUE)🔧 Ejecutando CI completo...$(NC)"
	bundle exec rake ci

# =============================================
# BASES DE DATOS
# =============================================

.PHONY: db-up
db-up:
	@echo "$(BLUE)🐳 Iniciando bases de datos...$(NC)"
	cd packages/better_auth && docker-compose up -d
	@echo "$(GREEN)✓ Bases de datos listas$(NC)"

.PHONY: db-down
db-down:
	@echo "$(BLUE)🐳 Deteniendo bases de datos...$(NC)"
	cd packages/better_auth && docker-compose down
	@echo "$(GREEN)✓ Bases de datos detenidas$(NC)"

# =============================================
# LIMPIEZA
# =============================================

.PHONY: clean
clean:
	@echo "$(BLUE)🧹 Limpiando workspace...$(NC)"
	rm -rf Gemfile.lock
	cd packages/better_auth && rm -rf Gemfile.lock *.gem coverage/
	cd packages/better_auth-rails && rm -rf Gemfile.lock *.gem coverage/
	@echo "$(GREEN)✓ Limpieza completada$(NC)"

# =============================================
# AYUDA
# =============================================

.PHONY: help
help:
	@echo "$(GREEN)Better Auth Ruby Workspace - Comandos disponibles:$(NC)"
	@echo ""
	@echo "$(YELLOW)Instalación:$(NC)"
	@echo "  make install       - Instala todas las dependencias"
	@echo "  make setup         - Configuración inicial"
	@echo ""
	@echo "$(YELLOW)Desarrollo:$(NC)"
	@echo "  make console       - Consola con todos los packages cargados"
	@echo "  make lint          - Revisa estilo en todos los packages"
	@echo "  make lint-fix      - Corrige estilo automáticamente"
	@echo ""
	@echo "$(YELLOW)Testing:$(NC)"
	@echo "  make test          - Tests de todo el workspace"
	@echo "  make test-core     - Solo better_auth (core)"
	@echo "  make test-rails    - Solo better_auth-rails"
	@echo "  make ci            - CI completo (lint + test)"
	@echo ""
	@echo "$(YELLOW)Bases de datos:$(NC)"
	@echo "  make db-up         - Inicia PostgreSQL, MySQL, Redis"
	@echo "  make db-down       - Detiene contenedores"
	@echo ""
	@echo "$(YELLOW)Utilidades:$(NC)"
	@echo "  make clean         - Limpia archivos temporales"
	@echo "  make help          - Muestra esta ayuda"
