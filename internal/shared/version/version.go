// Package version предоставляет информацию о версии и метаданных сборки бинарных файлов GophKeeper
package version

// Version содержит версию приложения
//
// Значение по умолчанию используется при локальном запуске через go run
// При релизной сборке значение должно переопределяться через ldflags
var Version = "dev"

// BuildDate содержит дату сборки бинарного файла
//
// Значение по умолчанию используется при локальном запуске через go run
// При релизной сборке значение должно переопределяться через ldflags
var BuildDate = "unknown"

// Commit содержит hash git-коммита, из которого был собран бинарный файл
//
// Значение по умолчанию используется при локальном запуске через go run
// При релизной сборке значение должно переопределяться через ldflags
var Commit = "unknown"

// Info описывает метаданные сборки приложения
type Info struct {
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	Commit    string `json:"commit"`
}

// Get возвращает текущие метаданные сборки приложения
func Get() Info {
	return Info{
		Version:   Version,
		BuildDate: BuildDate,
		Commit:    Commit,
	}
}
