import React, { MouseEventHandler, useEffect, useRef, useState } from "react";

type HeroProps = {
  descriptive: string;
  title: React.ReactNode;
  description: React.ReactNode;
  bouton1Text?: string;
  bouton2Text?: string;
  bouton1OnClick?: MouseEventHandler<HTMLButtonElement>;
  bouton2OnClick?: MouseEventHandler<HTMLButtonElement>;
  className?: string;
  isBlackTheme?: boolean;
  isTopPage?: boolean;
};

const Hero: React.FC<HeroProps> = ({
  descriptive,
  title,
  description,
  bouton1Text,
  bouton2Text,
  bouton1OnClick,
  bouton2OnClick,
  className,
  isBlackTheme = false,
  isTopPage = false,
}) => {
  const heroRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (isTopPage) {
        setIsVisible(true);
      }
    }, 100);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    const handleScroll = () => {
      if (heroRef.current) {
        const rect = heroRef.current.getBoundingClientRect();
        const windowHeight = window.innerHeight;
        if (rect.top <= windowHeight - 100 && !isVisible) {
          setIsVisible(true);
        }
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [isVisible]);

  return (
    <div>
      <section
        ref={heroRef}
        className={`w-full pt-10 flex flex-col justify-center items-center text-center p-4 transition-all duration-700 ease-out transform ${
          isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-20"
        } ${className}`}
      >
        {/* Descriptive tag */}
        <p
          className="text-xs md:text-sm uppercase tracking-widest mb-3 font-medium"
          style={{ color: "#60a5fa", letterSpacing: "0.18em" }}
        >
          {descriptive}
        </p>

        {/* Title */}
        <div
          className="text-4xl md:text-6xl font-bold mb-4"
          style={{ color: isBlackTheme ? "#e2e8f0" : "#0f172a" }}
        >
          {title}
        </div>

        {/* Description */}
        <p
          className={`max-w-2xl text-sm md:text-base leading-relaxed ${bouton1Text || bouton2Text ? "mb-8" : ""}`}
          style={{ color: isBlackTheme ? "#94a3b8" : "#64748b" }}
        >
          {description}
        </p>

        {/* Buttons */}
        {(bouton1Text || bouton2Text) && (
          <div className="flex mt-6 space-x-4">
            {bouton1Text && (
              <button
                onClick={bouton1OnClick}
                className="text-xs md:text-sm cursor-pointer font-bold py-4 px-8 rounded-lg transition-all border"
                style={{
                  background: isBlackTheme ? "#0d1828" : "#ffffff",
                  color: isBlackTheme ? "#e2e8f0" : "#0f172a",
                  borderColor: "#1b2d4f",
                  boxShadow: "0 4px 15px rgba(0,0,0,0.2)",
                }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.borderColor = "#3b82f6")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.borderColor = "#1b2d4f")
                }
              >
                {bouton1Text}
              </button>
            )}

            {bouton2Text && (
              <button
                onClick={bouton2OnClick}
                className="text-xs md:text-sm cursor-pointer font-bold py-4 px-8 rounded-lg transition-all"
                style={{
                  background: "linear-gradient(135deg, #1d4ed8, #3b82f6)",
                  color: "#ffffff",
                  boxShadow: "0 0 20px rgba(59,130,246,0.4)",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.boxShadow =
                    "0 0 28px rgba(59,130,246,0.6)";
                  e.currentTarget.style.transform = "translateY(-2px)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.boxShadow =
                    "0 0 20px rgba(59,130,246,0.4)";
                  e.currentTarget.style.transform = "translateY(0)";
                }}
              >
                {bouton2Text}
              </button>
            )}
          </div>
        )}
      </section>
    </div>
  );
};

export default Hero;
